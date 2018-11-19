// ms-compress: implements Microsoft compression algorithms
// Copyright (C) 2012  Jeffrey Bush  jeff@coderforlife.com
// Copyright (C) 2018 David Mulder <dmulder@suse.com>
//
// This library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <math.h>
#include "includes.h"
#include "lzhuff_xpress.h"

#ifndef PNTR_BITS
        #if SIZE_MAX == UINT64_MAX
                #define PNTR_BITS 64
        #elif SIZE_MAX == UINT32_MAX
                #define PNTR_BITS 32
        #elif SIZE_MAX == UINT16_MAX
                #define PNTR_BITS 16
        #else
                #error You must define PNTR_BITS to be the number of bits used for pointers
        #endif
#endif

#define GET_UINT16_RAW(x)               (((const uint8_t*)(x))[0]|(((const uint8_t*)(x))[1]<<8))
#define GET_UINT32_RAW(x)               (((const uint8_t*)(x))[0]|(((const uint8_t*)(x))[1]<<8)|(((const uint8_t*)(x))[2]<<16)|(((const uint8_t*)(x))[3]<<24))
#define SET_UINT16_RAW(x,val)   (((uint8_t*)(x))[0]=(uint8_t)(val), ((uint8_t*)(x))[1]=(uint8_t)((val)>>8))
#define SET_UINT32_RAW(x,val)   (((uint8_t*)(x))[0]=(uint8_t)(val), ((uint8_t*)(x))[1]=(uint8_t)((val)>>8), ((uint8_t*)(x))[2]=(uint8_t)((val)>>16), ((uint8_t*)(x))[3]=(uint8_t)((val)>>24))
#define GET_UINT16(x)                   GET_UINT16_RAW(x)
#define GET_UINT32(x)                   GET_UINT32_RAW(x)
#define SET_UINT16(x,val)               SET_UINT16_RAW(x,val)
#define SET_UINT32(x,val)               SET_UINT32_RAW(x,val)

#define SORT_SWITCH_TO_INSERT_LIMIT 90
#define MAX_OFFSET              0xFFFF
#define CHUNK_SIZE              0x10000
#define HASH_BITS               15
#define MAX_CHAIN               11
#define NICE_LENGTH             48
#define HUFF_BITS_MAX   15
#define SYMBOLS                 0x200
#define CHUNK_SIZE              0x10000
#define STREAM_END              0x100
#define STREAM_END_LEN_1        1
#define SYMBOLS                 0x200
#define HALF_SYMBOLS    0x100
#define MIN_DATA                HALF_SYMBOLS + 4 // the 512 Huffman lens + 2 uint16s for minimal bitstream

// Insertion-sorts syms[l, r) using conditions[syms[x]]
// Use insertion-sort so that it is stable, keeping symbols in increasing order
// This is only used at the tail end of merge_sort.
#define insertion_sort(type) \
static void insertion_sort_##type(uint16_t* syms, const type* const conditions, const uint_fast16_t len) \
{ \
	for (uint_fast16_t i = 1; i < len; ++i) \
	{ \
		const uint16_t x = syms[i]; \
		const type cond = conditions[x]; \
		uint_fast16_t j = i; \
		while (j > 0 && conditions[syms[j-1]] > cond) { syms[j] = syms[j-1]; --j; } \
		syms[j] = x; \
	} \
}
insertion_sort(uint8_t)
insertion_sort(uint32_t)

// Merge-sorts syms[l, r) using conditions[syms[x]]
// Use merge-sort so that it is stable, keeping symbols in increasing order
#define merge_sort(type) \
static void merge_sort_##type(uint16_t* syms, uint16_t* temp, const type* const conditions, const uint_fast16_t len) \
{ \
	if (len < SORT_SWITCH_TO_INSERT_LIMIT) \
	{ \
		insertion_sort_##type(syms, conditions, len); \
	} \
	else \
	{ \
		const uint_fast16_t m = len >> 1; \
		uint_fast16_t i = 0, j = 0, k = m; \
		merge_sort_##type(syms,   temp,   conditions, m      ); \
		merge_sort_##type(syms+m, temp+m, conditions, len - m); \
		memcpy(temp, syms, len*sizeof(uint16_t)); \
		while (j < m && k < len) syms[i++] = (conditions[temp[k]] < conditions[temp[j]]) ? temp[k++] : temp[j++]; \
		if (j < m)        { memcpy(syms+i, temp+j, (m  -j)*sizeof(uint16_t)); } \
		else if (k < len) { memcpy(syms+i, temp+k, (len-k)*sizeof(uint16_t)); } \
	} \
}
merge_sort(uint8_t)
merge_sort(uint32_t)

////////////////////////////// Bitstreams //////////////////////////////////////////////////////////
// A bitstream that allows either reading or writing, but not both at the same time.
// It reads uint16s for bits and 16 bits can be reliably read at a time.
// These are designed for speed and perform few checks. The burden of checking is on the caller.
// See the functions for assumptions they make that should be checked by the caller (asserts check
// these in the functions as well). Note that ctx->bits is >= 16 unless near the very end of the
// stream.

typedef struct
{
	uint8_t* out;
	uint16_t* pntr[2];	// the uint16's to write the data in mask to when there are enough bits
	uint32_t mask;		// The next bits to be read/written in the bitstream
	uint_fast8_t bits;	// The number of bits in mask that are valid
} OutputBitstream;

static void OutputBitstream_init(OutputBitstream *ctx, uint8_t* out)
{
	ctx->out = out+4;
	ctx->mask = 0;
	ctx->bits = 0;
	ctx->pntr[0] = (uint16_t*)(out);
	ctx->pntr[1] = (uint16_t*)(out+2);
}

static void WriteBits(OutputBitstream *ctx, uint32_t b, uint_fast8_t n)
{
	ctx->mask |= b << (32 - (ctx->bits += n));
	if (ctx->bits > 16)
	{
		SET_UINT16(ctx->pntr[0], ctx->mask >> 16);
		ctx->mask <<= 16;
		ctx->bits &= 0xF; //ctx->bits -= 16;
		ctx->pntr[0] = ctx->pntr[1];
		ctx->pntr[1] = (uint16_t*)(ctx->out);
		ctx->out += 2;
	}
}

static void WriteRawByte(OutputBitstream *ctx, uint8_t x)
{
	*ctx->out++ = x;
}

static void WriteRawUInt16(OutputBitstream *ctx, uint16_t x)
{
	SET_UINT16(ctx->out, x);
	ctx->out += 2;
}

static void WriteRawUInt32(OutputBitstream *ctx, uint32_t x)
{
	SET_UINT32(ctx->out, x);
	ctx->out += 4;
}

static void Finish(OutputBitstream *ctx)
{
	SET_UINT16(ctx->pntr[0], ctx->mask >> 16); // if !bits then mask is 0 anyways
	SET_UINT16_RAW(ctx->pntr[1], 0);
}

/////////////////// Dictionary /////////////////////////////////////////////////
// The dictionary system used for Xpress compression.
//
// TODO: ? Most of the compression time is spent in the dictionary - particularly Find

typedef struct
{
	// Window properties
	uint32_t WindowSize;
	uint32_t WindowMask;

	// The hashing function, which works progressively
	uint32_t HashSize;
	uint32_t HashMask;
	unsigned HashShift;

	const uint8_t *start, *end, *end2;
	const uint8_t** table;
	const uint8_t** window;
} XpressDictionary;

static void XpressDictionary_init(XpressDictionary *ctx, const uint8_t* start, const uint8_t* end)
{
	ctx->WindowSize = CHUNK_SIZE << 1;
	ctx->WindowMask = ctx->WindowSize-1;
	ctx->HashSize = 1 << HASH_BITS;
	ctx->HashMask = ctx->HashSize - 1;
	ctx->HashShift = (HASH_BITS+2)/3;
	ctx->table = (const uint8_t**)malloc(ctx->HashSize*sizeof(const uint8_t*));
	ctx->window = (const uint8_t**)malloc(ctx->WindowSize*sizeof(const uint8_t*));

	ctx->start = start;
	ctx->end = end;
	ctx->end2 = end - 2;
	memset(ctx->table, 0, ctx->HashSize*sizeof(const uint8_t*));
}

static uint32_t WindowPos(XpressDictionary *ctx, const uint8_t* x)
{
	return (uint32_t)((x - ctx->start) & ctx->WindowMask);
}

static uint_fast16_t HashUpdate(XpressDictionary *ctx, const uint_fast16_t h, const uint8_t c)
{
	return ((h<<ctx->HashShift) ^ c) & ctx->HashMask;
}


static uint32_t GetMatchLength(const uint8_t* a, const uint8_t* b, const uint8_t* end)
{
	// like memcmp but tells you the length of the match and optimized
	// assumptions: a < b < end, end4 = end - 4
	const uint8_t* b_start = b;
	uint8_t a0, b0;
	do
	{
		a0 = *a++;
		b0 = *b++;
	} while (b < end && a0 == b0);
	return (uint32_t)(b - b_start - 1);
}

static const uint8_t* Fill(XpressDictionary *ctx, const uint8_t* data)
{
	// equivalent to Add(data, CHUNK_SIZE)
	uint32_t pos;
	const uint8_t* endx;
	uint_fast16_t hash;
	if (data >= ctx->end2) { return ctx->end2; }
	pos = WindowPos(ctx, data); // either 0x00000 or CHUNK_SIZE
	endx = ((data + CHUNK_SIZE) < ctx->end2) ? data + CHUNK_SIZE : ctx->end2;
	hash = HashUpdate(ctx, data[0], data[1]);
	while (data < endx)
	{
		hash = HashUpdate(ctx, hash, data[2]);
		ctx->window[pos++] = ctx->table[hash];
		ctx->table[hash] = data++;
	}
	return endx;
}

static uint32_t Find(XpressDictionary *ctx, const uint8_t* data, uint32_t* offset)
{
#if PNTR_BITS <= 32
	const uint8_t* endx = ctx->end; // on 32-bit, + UINT32_MAX will always overflow
#else
	const uint8_t* endx = ((data + UINT32_MAX) < data || (data + UINT32_MAX) >= ctx->end) ? ctx->end : data + UINT32_MAX; // if overflow or past end use the end
#endif
	const uint8_t* xend = data - MAX_OFFSET;
	const uint8_t prefix0 = data[0], prefix1 = data[1];
	const uint8_t* x;
	uint32_t len = 2, chain_length = MAX_CHAIN;
	for (x = ctx->window[WindowPos(ctx, data)]; chain_length && x >= xend; x = ctx->window[WindowPos(ctx, x)], --chain_length)
	{
		if (x[0] == prefix0 && x[1] == prefix1)
		{
			// at ctx point the at least 3 bytes are matched (due to the hashing function forcing byte 3 to the same)
			const uint32_t l = GetMatchLength(x, data, endx);
			if (l > len)
			{
				*offset = (uint32_t)(data - x);
				len = l;
				if (len >= NICE_LENGTH) { break; }
			}
		}
	}
	return len;
}

typedef struct
{
	uint16_t codes[SYMBOLS];
	uint8_t lens[SYMBOLS];
} HuffmanEncoder;

#define HEAP_PUSH(x)                         \
{                                            \
	uint_fast16_t j; \
	heap[++heap_len] = x;                    \
	j = heap_len;              \
	while (weights[x] < weights[heap[j>>1]]) \
	{                                        \
		heap[j] = heap[j>>1]; j >>= 1;       \
	}                                        \
	heap[j] = x;                             \
}

#define HEAP_POP()                                  \
{                                                   \
	uint_fast16_t i = 1, t = heap[1] = heap[heap_len--]; \
	for (;;)                                        \
	{                                               \
		uint_fast16_t j = i << 1;                   \
		if (j > heap_len) { break; }                \
		if (j < heap_len && weights[heap[j+1]] < weights[heap[j]]) { ++j; } \
		if (weights[t] < weights[heap[j]]) { break; } \
		heap[i] = heap[j];                          \
		i = j;                                      \
	}                                               \
	heap[i] = t;                                    \
}

static const uint8_t* CreateCodes(HuffmanEncoder *ctx, uint32_t symbol_counts[SYMBOLS]) // 17 kb stack (for SYMBOLS == 0x200)
{
	uint32_t weights[SYMBOLS * 2]; // weights of nodes
	uint_fast16_t min, max;
	uint16_t code;
	// Creates Length-Limited Huffman Codes using an optimized version of the original Huffman algorithm
	// Does not always produce optimal codes
	// Algorithm from "In-Place Calculation of Minimum-Redundancy Codes" by A Moffat and J Katajainen
	// Code adapted from bzip2. See http://www.bzip.org/.
	memset(ctx->codes, 0, sizeof(ctx->codes));

	// Compute the initial weights (the weight is in the upper 24 bits, the depth (initially 0) is in the lower 8 bits
	weights[0] = 0;
	for (uint_fast16_t i = 0; i < SYMBOLS; ++i) { weights[i+1] = (symbol_counts[i] == 0 ? 1 : symbol_counts[i]) << 8; }

	for (;;)
	{
		// Build the initial heap
		int too_long;
		uint_fast16_t heap_len = 0, heap[SYMBOLS + 2] = { 0 }; // heap of symbols, 1 to heap_len
		uint_fast16_t n_nodes, parents[SYMBOLS * 2]; // parents of nodes, 1 to n_nodes
		for (uint_fast16_t i = 1; i <= SYMBOLS; ++i) { HEAP_PUSH(i); }

		// Build the tree (its a bottom-up tree)
		n_nodes = SYMBOLS;
		memset(parents, 0, sizeof(parents));
		while (heap_len > 1)
		{
			uint_fast16_t n1, n2;
			n1 = heap[1]; HEAP_POP();
			n2 = heap[1]; HEAP_POP();
			parents[n1] = parents[n2] = ++n_nodes;
			weights[n_nodes] = ((weights[n1]&0xffffff00)+(weights[n2]&0xffffff00)) | (1 + MAX((weights[n1]&0x000000ff),(weights[n2]&0x000000ff)));
			HEAP_PUSH(n_nodes);
		}

		// Create the actual length codes
		too_long = 0;
		for (uint_fast16_t i = 1; i <= SYMBOLS; ++i)
		{
			uint8_t j = 0;
			uint_fast16_t k = i;
			while (parents[k] > 0) { k = parents[k]; ++j; }
			ctx->lens[i-1] = j;
			if (j > HUFF_BITS_MAX) { too_long = 1; }
		}

		// If we had codes that were too long then we need to make all the weights smaller
		if (!too_long) { break; }
		for (uint_fast16_t i = 1; i <= SYMBOLS; ++i)
		{
			weights[i] = (1 + (weights[i] >> 9)) << 8;
		}
	}

	// Compute the values of the codes
	min = ctx->lens[0];
	max = min;
	for (uint_fast16_t i = 1; i < SYMBOLS; ++i)
	{
		if (ctx->lens[i] > max) { max = ctx->lens[i]; }
		else if (ctx->lens[i] < min) { min = ctx->lens[i]; }
	}
	code = 0;
	for (uint_fast16_t n = min; n <= max; ++n)
	{
		for (uint_fast16_t i = 0; i < SYMBOLS; ++i)
		{
			if (ctx->lens[i] == n) { ctx->codes[i] = code++; }
		}
		code <<= 1;
	}

	// Done!
	return ctx->lens;
}

static const uint8_t* CreateCodesSlow(HuffmanEncoder *ctx, uint32_t symbol_counts[SYMBOLS]) // 3 kb stack (for SYMBOLS == 0x200) [519kb stack]
{
	uint16_t syms_by_count[SYMBOLS], syms_by_len[SYMBOLS], temp[SYMBOLS]; // 3*2*512 = 3 kb
	uint_fast16_t len;
	// Creates Length-Limited Huffman Codes using the package-merge algorithm
	// Always produces optimal codes but is significantly slower than the Huffman algorithm
	memset(ctx->codes, 0, sizeof(ctx->codes));
	memset(ctx->lens,  0, sizeof(ctx->lens));

	// Fill the syms_by_count and syms_by_length with the symbols that were found
	len = 0;
	for (uint_fast16_t i = 0; i < SYMBOLS; ++i) { if (symbol_counts[i]) { syms_by_count[len] = (uint16_t)i; syms_by_len[len++] = (uint16_t)i; ctx->lens[i] = HUFF_BITS_MAX; } }

	////////// Get the Huffman lengths //////////
	merge_sort_uint32_t(syms_by_count, temp, symbol_counts, len); // sort by the counts
	if (len == 1)
	{
		ctx->lens[syms_by_count[0]] = 1; // never going to happen, but the code below would probably assign a length of 0 which is not right
	}
	else
	{
		///// Package-Merge Algorithm /////
		typedef struct _collection // 516 bytes each
		{
			uint8_t symbols[SYMBOLS];
			uint_fast16_t count;
		} collection;
		collection _cols[SYMBOLS], _next_cols[SYMBOLS],
			*cols = _cols, *next_cols = _next_cols; // 2*516*512 = 516 kb (not on stack any more)
		uint_fast16_t cols_len = 0, next_cols_len = 0;

		// Start at the lowest value row, adding new collection
		for (uint_fast16_t j = 0; j < HUFF_BITS_MAX; ++j)
		{
			uint_fast16_t cols_pos = 0, pos = 0;
			collection* temp_cols;

			// All but the last one/none get added to collections
			while ((cols_len-cols_pos + len-pos) > 1)
			{
				memset(next_cols+next_cols_len, 0, sizeof(collection));
				for (uint_fast16_t i = 0; i < 2; ++i) // hopefully unrolled...
				{
					if (pos >= len || (cols_pos < cols_len && cols[cols_pos].count < symbol_counts[syms_by_count[pos]]))
					{
						// Add cols[cols_pos]
						next_cols[next_cols_len].count += cols[cols_pos].count;
						for (uint_fast16_t s = 0; s < SYMBOLS; ++s)
						{
							next_cols[next_cols_len].symbols[s] += cols[cols_pos].symbols[s];
						}
						++cols_pos;
					}
					else
					{
						// Add syms[pos]
						next_cols[next_cols_len].count += symbol_counts[syms_by_count[pos]];
						++next_cols[next_cols_len].symbols[syms_by_count[pos]];
						++pos;
					}
				}
				++next_cols_len;
			}

			// Leftover gets dropped
			if (cols_pos < cols_len)
			{
				const uint8_t* const syms = cols[cols_pos].symbols;
				for (uint_fast16_t i = 0; i < SYMBOLS; ++i) { ctx->lens[i] -= syms[i]; }
			}
			else if (pos < len)
			{
				--ctx->lens[syms_by_count[pos]];
			}

			// Move the next_collections to the current collections
			temp_cols = cols; cols = next_cols; next_cols = temp_cols;
			cols_len = next_cols_len;
			next_cols_len = 0;
		}

		////////// Create Huffman codes from lengths //////////
		merge_sort_uint8_t(syms_by_len, temp, ctx->lens, len); // Sort by the code lengths
		for (uint_fast16_t i = 1; i < len; ++i)
		{
			// Code is previous code +1 with added zeroes for increased code length
			ctx->codes[syms_by_len[i]] = (ctx->codes[syms_by_len[i-1]] + 1) << (ctx->lens[syms_by_len[i]] - ctx->lens[syms_by_len[i-1]]);
		}
	}

	return ctx->lens;
}

static void EncodeSymbol(HuffmanEncoder *ctx, uint_fast16_t sym, OutputBitstream *bits)
{
	WriteBits(bits, ctx->codes[sym], ctx->lens[sym]);
}

#undef HEAP_PUSH
#undef HEAP_POP

////////////////////////////// Compression Functions ///////////////////////////////////////////////
static size_t xh_compress_lz77(const uint8_t* in, int32_t /* * */ in_len, const uint8_t* in_end, uint8_t* out, uint32_t symbol_counts[SYMBOLS], XpressDictionary* d)
{
	int32_t rem = /* * */ in_len;
	uint32_t mask;
	const uint8_t* in_orig = in, *out_orig = out;
	uint32_t* mask_out;
	uint8_t i;

	Fill(d, in);
	memset(symbol_counts, 0, SYMBOLS*sizeof(uint32_t));

	////////// Count the symbols and write the initial LZ77 compressed data //////////
	// A uint32 mask holds the status of each subsequent byte (0 for literal, 1 for match)
	// Literals are stored using a single byte for their value
	// Matches are stored in the following manner:
	//   Symbol: a byte (doesn't include the 0x100)
	//   Offset: a uint16 (doesn't include the highest set bit)
	//   Length: for length-3:
	//     0x0000 <= length <  0x0000000F  nothing (contained in symbol)
	//     0x000F <= length <  0x0000010E  length-3-0xF as byte
	//     0x010E <= length <= 0x0000FFFF  0xFF + length-3 as uint16
	//     0xFFFF <  length <= 0xFFFFFFFF  0xFF + 0x0000 + length-3 as uint32
	// The number of bytes between uint32 masks is >=32 and <=192 (6*32)
	//   with the exception that the a length > 0x10002 could be found, but this is longer than a chunk and would immediately end the chunk
	//   if it is the last one, then we need 4 additional bytes, but we don't have to take it into account in any other way
	// The number of represented bytes between uint32 masks is at least the number of actual bytes between them
	while (rem > 0)
	{
		mask = 0;
		mask_out = (uint32_t*)out;
		out += 4;

		// Go through each bit
		for (i = 0; i < 32 && rem > 0; ++i)
		{
			uint32_t len, off;
			mask >>= 1;
			if (rem >= 3 && (len = Find(d, in, &off)) >= 3)
			{
				uint8_t off_bits, sym;
				// TODO: allow len > rem (chunk-spanning matches)
				if (len > (uint32_t)rem) { len = rem; }
				in += len; rem -= len;

				// Create the symbol
				len -= 3;
				mask |= 0x80000000; // set the highest bit
				off_bits = (uint8_t)log2((uint16_t)(off|1)); // |1 prevents taking the log2 of 0 (undefined) and makes 0 -> 1 which is what we want
				sym = (off_bits << 4) | (uint8_t)MIN(0xF, len);
				++symbol_counts[0x100 | sym];
				off ^= 1 << off_bits; // clear highest bit

				// Write symbol / offset / length
				*out = sym; SET_UINT16_RAW(out+1, off); out += 3;
				if (len > 0xFFFF) { *out = 0xFF; SET_UINT16_RAW(out+1, 0); SET_UINT32_RAW(out+3, len); out += 7; }
				else if (len >= 0xFF + 0xF) { *out = 0xFF; SET_UINT16_RAW(out+1, len); out += 3; }
				else if (len >= 0xF)        { *out++ = (uint8_t)(len - 0xF); }
			}
			else
			{
				// Write the literal value (which is the symbol)
				++symbol_counts[*out++ = *in++];
				--rem;
			}
		}

		// Save mask
		SET_UINT32_RAW(mask_out, mask);
	}

	// Set the total number of bytes read from in
	/* *in_len -= rem; */
	mask >>= (32-i); // finish moving the value over
	if (in_orig+ /* * */ in_len == in_end)
	{
		// Add the end of stream symbol
		if (i == 32)
		{
			// Need to add a new mask since the old one is full with just one bit set
			SET_UINT32_RAW(out, 1);
			out += 4;
		}
		else
		{
			// Add to the old mask
			mask |= 1 << i; // set the highest bit
		}
		SET_UINT32_RAW(out, 0);
		out += 3;
		++symbol_counts[STREAM_END];
	}
	SET_UINT32_RAW(mask_out, mask);

	// Return the number of bytes in the output
	return out - out_orig;
}

static size_t xh_compress_no_matching(const uint8_t* in, size_t in_len, int is_end, uint8_t* out, uint32_t symbol_counts[SYMBOLS])
{
	const uint8_t* in_end = in + in_len, *in_endx = in_end - 32;
	const uint8_t* out_orig = out;
	size_t rem;
	memset(symbol_counts, 0, SYMBOLS*sizeof(uint32_t));
	while (in < in_endx)
	{
		SET_UINT32_RAW(out, 0); out += 4;
		memcpy(out, in, 32); out += 32;
		for (uint_fast8_t i = 0; i < 32; ++i) { ++symbol_counts[*in++]; }
	}
	rem = in_end - in; // 1 - 32
	SET_UINT32_RAW(out, 0); out += 4;
	memcpy(out, in, rem); out += rem;
	for (uint_fast8_t i = 0; in < in_end; ++i) { ++symbol_counts[*in++]; }
	if (is_end)
	{
		// Add the end of stream symbol
		if (rem == 32) { SET_UINT32_RAW(out, 1); out += 4; }
		else { const uint32_t mask = 1 << rem; SET_UINT32_RAW(out - rem - 4, mask); }
		SET_UINT32_RAW(out, 0);
		out += 3;
		++symbol_counts[STREAM_END];
	}
	return out - out_orig;
}

static size_t xh_calc_compressed_len(const uint8_t lens[SYMBOLS], const uint32_t symbol_counts[SYMBOLS], const size_t buf_len)
{
	size_t sym_bits = 16; // we always have at least an extra 16-bits of 0s as the "end-of-chunk"
	uint32_t literal_syms = 0, match_syms = 0;
	for (uint_fast16_t i = 0; i < 0x100; ++i) { sym_bits += lens[i] * symbol_counts[i]; literal_syms += symbol_counts[i]; }
	for (uint_fast16_t i = 0x100; i < SYMBOLS; ++i) { sym_bits += (lens[i] + ((i>>4)&0xF)) * symbol_counts[i]; match_syms += symbol_counts[i]; }
	return (sym_bits+15)/16*2 + (buf_len - (literal_syms + match_syms*3 + (literal_syms+match_syms+31)/32*4)); // compressed size of all symbols after accounting for 16-bit alignment and extra bytes
}

static size_t xh_calc_compressed_len_no_matching(const uint8_t lens[SYMBOLS], const uint32_t symbol_counts[SYMBOLS])
{
	size_t sym_bits = 16;
	for (uint_fast16_t i = 0; i <= 0x100; ++i) { sym_bits += lens[i] * symbol_counts[i]; }
	return (sym_bits+15)/16*2;
}

static void xh_compress_encode(const uint8_t* in, const uint8_t* in_end, uint8_t* out, HuffmanEncoder *encoder)
{
	// Write the encoded compressed data
	// This involves parsing the LZ77 compressed data and re-writing it with the Huffman codes
	OutputBitstream bstr;
	OutputBitstream_init(&bstr, out);
	while (in < in_end)
	{
		// Handle a fragment
		// Bit mask tells us how to handle the next 32 symbols, go through each bit
		uint_fast16_t i;
		uint32_t mask;
		for (i = 32, mask = GET_UINT32_RAW(in), in += 4; mask && in < in_end; --i, mask >>= 1)
		{
			if (mask & 1) // offset / length symbol
			{
				// Get the LZ77 sym and offset
				const uint8_t sym = *in++;
				const uint_fast16_t off = GET_UINT16_RAW(in); in += 2;

				// Write the Huffman code
				EncodeSymbol(encoder, 0x100 | sym, &bstr);

				// Write extra length bytes
				if ((sym & 0xF) == 0xF)
				{
					const uint8_t len8 = *in++;
					WriteRawByte(&bstr, len8);
					if (len8 == 0xFF)
					{
						const uint16_t len16 = GET_UINT16_RAW(in); in += 2;
						WriteRawUInt16(&bstr, len16);
						if (len16 == 0) { WriteRawUInt32(&bstr, GET_UINT32_RAW(in)); in += 4; }
					}
				}

				// Write offset bits (off already has the high bit cleared)
				WriteBits(&bstr, off, sym >> 4);
			}
			else
			{
				// Write the literal symbol
				EncodeSymbol(encoder, *in++, &bstr);
			}
		}
		// Write the remaining literal symbols
		for (const uint8_t* end = MIN(in+i, in_end); in != end; ++in) { EncodeSymbol(encoder, *in, &bstr); }
	}

	// Write end of stream symbol and return insufficient buffer or the compressed size
	Finish(&bstr); // make sure that the write stream is finished writing
}

int lzhuff_xpress_compress(const uint8_t* in, size_t in_len, uint8_t* out, size_t* _out_len)
{
	uint8_t* buf;
	const uint8_t* out_orig;
	const uint8_t* in_end;
	size_t out_len;
	uint32_t symbol_counts[SYMBOLS]; // 4*512 = 2 kb
	XpressDictionary d;
	HuffmanEncoder encoder;
	if (in_len == 0) { *_out_len = 0; return 0; }

	buf = (uint8_t*)malloc((in_len >= CHUNK_SIZE) ? 0x1200C : ((in_len + 31) / 32 * 36 + 4 + 8)); // for every 32 bytes in "in" we need up to 36 bytes in the temp buffer + maybe an extra uint32 length symbol + up to 7 for the EOS (+1 for alignment)
	if (buf == NULL) { return ENOMEM; }

	out_orig = out;
	in_end = in+in_len;
	out_len = *_out_len;
	XpressDictionary_init(&d, in, in_end);

	// Go through each chunk except the last
	while (in_len > CHUNK_SIZE)
	{
		////////// Perform the initial LZ77 compression //////////
		size_t buf_len = xh_compress_lz77(in, CHUNK_SIZE, in_end, buf, symbol_counts, &d);

		////////// Create the Huffman codes/lens and Calculate the compressed output size //////////
		const uint8_t* lens = CreateCodes(&encoder, symbol_counts);
		size_t comp_len = xh_calc_compressed_len(lens, symbol_counts, buf_len);

		////////// Guarantee Max Compression Size //////////
		// This is required to guarantee max compressed size
		// It is very rare that it is used (mainly medium-high uncompressible data)
		if (comp_len > CHUNK_SIZE+2) // + 2 for alignment
		{
			buf_len = xh_compress_no_matching(in, CHUNK_SIZE, 0, buf, symbol_counts);
			lens = CreateCodesSlow(&encoder, symbol_counts);
			comp_len = xh_calc_compressed_len_no_matching(lens, symbol_counts);
		}

		////////// Output Huffman prefix codes as lengths and Encode compressed data //////////
		if (out_len < HALF_SYMBOLS + comp_len) { DEBUG(1, ("Xpress Huffman Compression Error: Insufficient buffer\n")); free(buf); return ENOBUFS; }
		for (const uint8_t* end = lens + SYMBOLS; lens < end; lens += 2) { *out++ = lens[0] | (lens[1] << 4); }
		xh_compress_encode(buf, buf+buf_len, out, &encoder);
		in += CHUNK_SIZE; in_len -= CHUNK_SIZE;
		out += comp_len; out_len -= HALF_SYMBOLS + comp_len;
	}

	// Do the last chunk
	if (in_len == 0)
	{
		if (out_len < MIN_DATA) { DEBUG(1, ("Xpress Huffman Compression Error: Insufficient buffer\n")); free(buf); return ENOBUFS; }
		memset(out, 0, MIN_DATA);
		out[STREAM_END>>1] = STREAM_END_LEN_1;
		out += MIN_DATA;
	}
	else
	{
		////////// Perform the initial LZ77 compression //////////
		size_t buf_len = xh_compress_lz77(in, (int32_t)in_len, in_end, buf, symbol_counts, &d);

		////////// Create the Huffman codes/lens and Calculate the compressed output size //////////
		const uint8_t* lens = CreateCodes(&encoder, symbol_counts);
		size_t comp_len = xh_calc_compressed_len(lens, symbol_counts, buf_len);

		////////// Guarantee Max Compression Size //////////
		// This is required to guarantee max compressed size
		// It is very rare that it is used (mainly medium-high uncompressible data)
		if (comp_len > in_len+36) // +36 for alignment and end of stream (because it causes a different symbol to need 9 bits)
		{
			buf_len = xh_compress_no_matching(in, in_len, 1, buf, symbol_counts);
			lens = CreateCodesSlow(&encoder, symbol_counts);
			comp_len = xh_calc_compressed_len_no_matching(lens, symbol_counts);
		}

		////////// Output Huffman prefix codes as lengths and Encode compressed data //////////
		if (out_len < HALF_SYMBOLS + comp_len) { DEBUG(1, ("Xpress Huffman Compression Error: Insufficient buffer\n")); free(buf); return ENOBUFS; }
		for (const uint8_t* end = lens + SYMBOLS; lens < end; lens += 2) { *out++ = lens[0] | (lens[1] << 4); }
		xh_compress_encode(buf, buf+buf_len, out, &encoder);
		out += comp_len;
	}

	// Cleanup
	free(buf);

	// Return the total number of compressed bytes
	*_out_len = out - out_orig;
	return 0;
}

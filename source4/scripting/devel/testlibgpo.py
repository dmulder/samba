#!/usr/bin/env python

# Copyright Matthieu Patou <mat@matws.net> 2013

import sys

sys.path.insert(0, "bin/python")

import samba.gpo as gpo
#get unix path
#Send LDAP Request - Have a place to receive it
#Use the information to fill up some structures. Get the info.
name_version = gpo.gpo_get_sysvol_gpt_version("/home/lukem/sambas/gsoc.samba.org/state/sysvol/gsoc.samba.org/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}")
print name_version
p = ads_parse_gp_ext("string")
#Have info, then use that information to fill up a group policy structure,
#use that structure to then identify importance
#after some basic arithmetic evaluation is done (C wrapper for *importance_to_samba(ADS_STRUCT *ads, GROUP_POLICY_OBJECT *gpo) returns true or false
#if it is NOT ignore here, continue next iteration, get the next GPO
#if it is important, let us update the samba database, in terms of importance.
#The rest will be inotify because it will maybe use the bash $ terminal to just call this script repeatedly

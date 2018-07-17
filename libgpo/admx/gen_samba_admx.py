#!/usr/bin/env python
import xml.etree.ElementTree as etree
from xml.dom import minidom
import optparse, os.path, re, sys, uuid

def policy_definitions_resources():
    policyDefinitionResources = etree.Element('policyDefinitionResources')
    policyDefinitionResources.set('revision', '1.0')
    policyDefinitionResources.set('schemaVersion', '1.0')
    etree.SubElement(policyDefinitionResources, 'displayName')
    etree.SubElement(policyDefinitionResources, 'description')
    resources = etree.SubElement(policyDefinitionResources, 'resources')
    stringTable = etree.SubElement(resources, 'stringTable')
    presentationTable = etree.SubElement(resources, 'presentationTable')

    return (policyDefinitionResources, stringTable, presentationTable)

def policy_definitions(stringTable, presentationTable):
    policyDefinitions = etree.Element('policyDefinitions')
    policyDefinitions.set('revision', '1.0')
    policyDefinitions.set('schemaVersion', '1.0')

    policyNamespaces = etree.SubElement(policyDefinitions, 'policyNamespaces')

    target = etree.SubElement(policyNamespaces, 'target')
    target.set('namespace', 'Samba.Policies.Samba')
    target.set('prefix', 'samba')

    using = etree.SubElement(policyNamespaces, 'using')
    using.set('namespace', 'Samba.Policies')
    using.set('prefix', 'SambaBase')

    using = etree.SubElement(policyNamespaces, 'using')
    using.set('namespace', 'Microsoft.Policies.Windows')
    using.set('prefix', 'windows')

    resources = etree.SubElement(policyDefinitions, 'resources')
    resources.set('minRequiredRevision', '1.0')

    categories = etree.SubElement(policyDefinitions, 'categories')

    samba = etree.SubElement(categories, 'category')
    samba.set('displayName', '$(string.CAT_3338C1DD_8A00_4273_8547_158D8B8C19E9)')
    samba.set('name', 'CAT_3338C1DD_8A00_4273_8547_158D8B8C19E9')
    samba_disp_name = etree.SubElement(stringTable, 'string')
    samba_disp_name.set('id', 'CAT_3338C1DD_8A00_4273_8547_158D8B8C19E9')
    samba_disp_name.text = 'Samba'

    smb_conf_cat = 'CAT_%s' % str(uuid.uuid5(uuid.NAMESPACE_OID, 'smb.conf')).replace('-', '_').upper()
    smb_conf = etree.SubElement(categories, 'category')
    smb_conf.set('displayName', '$(string.%s)' % smb_conf_cat)
    smb_conf.set('name', smb_conf_cat)
    smb_conf_disp_name = etree.SubElement(stringTable, 'string')
    smb_conf_disp_name.set('id', smb_conf_cat)
    smb_conf_disp_name.text = 'smb.conf'
    parentCategory = etree.SubElement(smb_conf, 'parentCategory')
    parentCategory.set('ref', 'CAT_3338C1DD_8A00_4273_8547_158D8B8C19E9')

    policies = etree.SubElement(policyDefinitions, 'policies')

    return (policyDefinitions, policies)

def add_policy_from_samba_conf(path, policies, stringTable, presentationTable):
    smb_conf_cat = 'CAT_%s' % str(uuid.uuid5(uuid.NAMESPACE_OID, 'smb.conf')).replace('-', '_').upper()
    for dirname, dirs, files in os.walk(path):
        for fname in files:
            full_path = os.path.join(dirname, fname)
            if not os.path.isdir(full_path) and \
              os.path.splitext(full_path)[-1] == '.xml':
                with open(full_path, 'r') as xml:
                    text = re.sub('\&\w+\.\w+\;', '', xml.read())
                    text = '<opts>%s</opts>' % text
                    opts = etree.fromstring(text)
                    for opt in opts.getchildren():
                        if opt.get('context') != 'G':
                            continue
                        opt_name = opt.get('name')
                        if opt_name == 'idmap config DOMAIN : OPTION':
                            continue # we can't customize the option name
                        opt_type = opt.get('type')
                        opt_id = 'POL_%s' % str(uuid.uuid5(uuid.NAMESPACE_OID, opt_name)).replace('-', '_').upper()
                        policy = etree.SubElement(policies, 'policy')
                        policy.set('class', 'Both')
                        policy.set('displayName', '$(string.%s)' % opt_id)
                        string = etree.SubElement(stringTable, 'string')
                        string.set('id', opt_id)
                        string.text = opt_name

                        default = None
                        example = ''
                        for val in opt.findall('value'):
                            if val.get('type') == 'default':
                                default = val.text
                            if val.get('type') == 'example':
                                example += '\n\nExample: %s' % val.text

                        desc = etree.tostring(opt.find('description'),
                                              method='text')
                        desc = re.sub(' +|\t', ' ', re.sub('\n\t', ' ',
                            desc.decode())).strip()
                        policy.set('explainText',
                            '$(string.%s_Help)' % opt_id)
                        explain = etree.SubElement(stringTable, 'string')
                        explain.set('id', '%s_Help' % opt_id)
                        explain.text = desc + example

                        policy.set('key', 'Software\Policies\Samba\smb_conf')
                        policy.set('name', opt_id)

                        pol_id = 'POL_%s' % str(uuid.uuid5(uuid.NAMESPACE_OID, '%s_presentation' % opt_id)).replace('-', '_').upper()
                        policy.set('presentation',
                                   '$(presentation.%s)' % pol_id)
                        presentation = etree.SubElement(presentationTable,
                                                        'presentation')
                        presentation.set('id', pol_id)
                        if opt_type in ['string', 'ustring',
                                        'cmdlist', 'enum', 'list']:
                            textbox = etree.SubElement(presentation, 'textBox')
                            refid = 'TXT_%s' % str(uuid.uuid5(uuid.NAMESPACE_OID, '%s_text' % opt_id)).replace('-', '_').upper()
                            textbox.set('refId', refid)
                            label = etree.SubElement(textbox, 'label')
                            label.text = opt_name
                            if default:
                                defaultvalue = etree.SubElement(textbox,
                                                                'defaultValue')
                                defaultvalue.text = default
                        elif opt_type in ['boolean', 'boolean-rev']:
                            checkbox = etree.SubElement(presentation,
                                                        'checkBox')
                            refid = 'CHK_%s' % str(uuid.uuid5(uuid.NAMESPACE_OID, '%s_boolean' % opt_id)).replace('-', '_').upper()
                            checkbox.set('refId', refid)
                            if default and default.lower() == 'yes':
                                checkbox.set('defaultChecked', 'true')
                            checkbox.text = opt_name
                        elif opt_type in ['integer', 'bytes']:
                            decimaltextbox = etree.SubElement(presentation,
                                                              'decimalTextBox')
                            refid = 'DXT_%s' % str(uuid.uuid5(uuid.NAMESPACE_OID, '%s_decimal' % opt_id)).replace('-', '_').upper()
                            decimaltextbox.set('refId', refid)
                            if default and default.isdigit():
                                decimaltextbox.set('defaultValue', default)
                        else:
                            raise Exception('Type %s not implemented!' %
                                            opt_type)

                        parentCategory = etree.SubElement(policy,
                                                          'parentCategory')
                        parentCategory.set('ref', smb_conf_cat)
                        supportedOn = etree.SubElement(policy, 'supportedOn')
                        supportedOn.set('ref', 'SUPPORTED_WIN7')

                        elements = etree.SubElement(policy, 'elements')
                        if opt_type in ['string', 'ustring',
                                        'cmdlist', 'enum', 'list']:
                            text = etree.SubElement(elements, 'text')
                            refid = 'TXT_%s' % str(uuid.uuid5(uuid.NAMESPACE_OID, '%s_text' % opt_id)).replace('-', '_').upper()
                            text.set('id', refid)
                            text.set('valueName', opt_name)
                        elif opt_type in ['boolean', 'boolean-rev']:
                            boolean = etree.SubElement(elements, 'boolean')
                            refid = 'CHK_%s' % str(uuid.uuid5(uuid.NAMESPACE_OID, '%s_boolean' % opt_id)).replace('-', '_').upper()
                            boolean.set('id', refid)
                            boolean.set('valueName', opt_name)
                        elif opt_type in ['integer', 'bytes']:
                            decimal = etree.SubElement(elements, 'decimal')
                            refid = 'DXT_%s' % str(uuid.uuid5(uuid.NAMESPACE_OID, '%s_decimal' % opt_id)).replace('-', '_').upper()
                            decimal.set('id', refid)
                            decimal.set('valueName', opt_name)
                        else:
                            raise Exception('Type %s not implemented!' %
                                            opt_type)

def gen_smb_conf_admx(docs_xml_dir, out_dir):
    adml, stringTable, presentationTable = policy_definitions_resources()
    admx, policies = policy_definitions(stringTable, presentationTable)

    path = os.path.join(docs_xml_dir, 'smbdotconf')
    add_policy_from_samba_conf(path, policies, stringTable, presentationTable)

    admx_fname = os.path.join(out_dir, 'samba.admx')
    with open(admx_fname, 'w') as f:
        xmlstr = minidom.parseString(etree.tostring(admx)).toprettyxml(indent="  ")
        f.write(xmlstr.encode('utf-8'))

    adml_fname = os.path.join(out_dir, 'en-US/samba.adml')
    adml_parent = os.path.dirname(adml_fname)
    if not os.path.exists(adml_parent):
        os.mkdir(adml_parent)
    with open(adml_fname, 'w') as f:
        xmlstr = minidom.parseString(etree.tostring(adml)).toprettyxml(indent="  ")
        f.write(xmlstr.encode('utf-8'))

if __name__ == "__main__":
    parser = optparse.OptionParser('Generator for samba admx sources')
    parser.add_option('--install-dir',
                      help='Directory to install admx files into')
    parser.add_option('--docs-xml-dir',
                      help='Location of the samba docs-xml directory')
    (opts, args) = parser.parse_args()
    if opts.install_dir:
        install_dir = opts.install_dir
    else:
        install_dir = os.path.abspath(os.path.dirname(sys.argv[0]))
    if opts.docs_xml_dir:
        docs_xml_dir = opts.docs_xml_dir
    else:
        docs_xml_dir = os.path.abspath(os.path.join(install_dir,
                                                    '../../docs-xml'))

    gen_smb_conf_admx(docs_xml_dir, install_dir)

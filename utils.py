import re
import os


def get_configurations(data):
    confs = set()
    versions = set()

    nodes = data.get('configurations', {}).get('nodes', [])
    for node in nodes:
        cpes = node.get('cpe', [])
        for cpe in cpes:
            if cpe.get('vulnerable', True):
                cpe_str = cpe.get('cpe22Uri')
                if cpe_str:
                    confs.add(cpe_str)
                if cpe.get('versionEndIncluding') is not None:
                    versions.add(cpe.get('versionEndIncluding'))
                if cpe.get('versionEndIncluding') is not None:
                    versions.add(cpe.get('versionEndExcluding'))

    return confs, versions



def cpe_is_app(cpe_str):
    return cpe_str[len('cpe:/'):][0] == 'a'


def extract_vendor_product_version(cpe_str):
    cpe_parts = cpe_str.split(':')[2:]
    version = None
    if len(cpe_parts) >= 3:
        version = cpe_parts[2]

    return cpe_parts[0], cpe_parts[1], version


stop_words = set(['in', 'the', 'a', 'an', 'the', 'when'])


def guess_package_name(description):
    first_sentence = ''

    # take first sentence
    regexp = re.compile('.*\. ')
    match = regexp.match(description)
    if not match:
        regexp = re.compile('.*\.$')
        match = regexp.match(description)
    if not match:
        return ''

    first_sentence = match.group()
    regexp = re.compile('[A-Z][A-Za-z0-9-:]*')
    suspects = regexp.findall(first_sentence)

    result = []
    for s in suspects:
        if not s.lower() in stop_words:
            result.append(s.lower())
            if len(result) == 3:
                break

    return set(result)


def generate_yaml(cve_id, cvss, description, pkg_name, references):
    template = """---
cve: {cve_id}
title: CVE in {pkg_name}
description: >
    {desc}
cvss_v2: {cvss}
references:
    - {refs}
affected:
    - groupId: {g}
      artifactId: {a}
      version:
        - "{v}"
fixedin:
    - "{fixed_in}"
"""

    _, year, cid = cve_id.split('-')
    try:
        ws = os.environ.get('WORKSPACE')
        db_dir = os.path.join(ws, 'database')
        year_dir = os.path.join(db_dir, year)
        os.makedirs(year_dir)
    except FileExistsError:
        pass

    yaml_file = os.path.join(year_dir, cid + '.yaml')
    with open(yaml_file, 'w') as f:
        g, a = pkg_name.split(':')
        refs = '    - '.join([x + '\n' for x in references])
        data = template.format(cve_id=cve_id, pkg_name=pkg_name, cvss=cvss, desc=description, g=g, a=a, v='!FIXME!',
                               refs=refs, fixed_in='!FIXME!')
        f.write(data)

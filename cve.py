#!/usr/bin/env python3

import json
import subprocess
from utils import get_configurations, cpe_is_app, extract_vendor_product_version, guess_package_name, generate_yaml


def run():
    with open('nvdcve.json') as f:
        data = json.load(f)

        for d in data.get('CVE_Items'):

            cve_id = d.get('cve', {}).get('CVE_data_meta', {}).get('ID')
            print('Found ' + cve_id)

            references_data = d.get('cve', {}).get('references', {}).get('reference_data', [])
            references = [x.get('url') for x in references_data]

            print('Found ' + cve_id)

            confs, additional_versions = get_configurations(d)
            vendor = set()
            product = set()
            version = set()
            if not confs:
                continue
            for c in confs:
                if cpe_is_app(c):
                    ven, prod, ver = extract_vendor_product_version(c)
                    vendor.add(ven)
                    product.add(prod)
                    version.add(ver)
                    print('vendor: ' + ven + ' product: ' + prod)
                    if ver:
                        print('version: ' + str(ver))

            version.update(additional_versions)
            descriptions = d.get('cve', {}).get('description', {}).get('description_data', [])

            pkg_name_candidates = set()
            for description in descriptions:
                if description.get('lang') == 'en':
                    # this is what we are looking for!
                    desc = description.get('value', '')
                    names = guess_package_name(desc)
                    pkg_name_candidates.update(names)
                    description = description.get('value')
                    break
            else:
                print('Missing description')

            cvss = d.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore')
            print('CVSS: ' + str(cvss))

            if not product or not vendor:
                continue

            query_template = 'product:( {product} )  AND  vendor:( {vendor} )'
            product.update(pkg_name_candidates)
            query = query_template.format(product=' '.join(product), vendor=''.join(vendor))
            query = query.replace(':', ' ')
            print(query)

            cpe2pkg_output = subprocess.check_output('java -jar cpe2pkg.jar "' + query + '"', shell=True, universal_newlines=True)
            print(cpe2pkg_output)

            cpe2pkg_lines = cpe2pkg_output.split('\n')

            hit = False
            if len(cpe2pkg_lines) >= 2 and cpe2pkg_lines[1]:
                for cpepkg in cpe2pkg_lines[1:]:
                    if not cpepkg:
                        continue
                    ga = cpepkg.split()[1]
                    print('possible package name: ' + ga)

                    with open('packages') as pf:
                        for line in pf.readlines():
                            g, a, v = line.split(',')
                            if '{}:{}'.format(g, a) == ga:
                                affected_versions = version & set(v.split())
                                if affected_versions:
                                    print('affected version: ' + str(affected_versions))
                                    generate_yaml(cve_id, cvss, description, '{}:{}'.format(g, a), references)
                                    print(cpe2pkg_lines)
                                    hit = True
                                else:
                                    print('false positive ' + str(version))

                    if hit:
                        break


if __name__ == '__main__':
    run()

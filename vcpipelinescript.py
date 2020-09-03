import sys
import requests
import argparse
import logging
from lxml import etree
from io import BytesIO
import json
import datetime

from veracode_api_py import VeracodeAPI as vapi

from helpers import constants

def creds_expire_days_warning():
    creds = vapi().get_creds()
    exp = datetime.datetime.strptime(creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
    delta = exp - datetime.datetime.now().astimezone() #we get a datetime with timezone...
    if (delta.days < 7):
        print('These API credentials expire ', creds['expiration_ts'])

def getapplication(appid):
    appinfo = vapi().get_app(legacy_id=appid)
    appinfo = appinfo['_embedded']['applications'][0]
    return appinfo

def getpolicy(appinfo):
    policy_guid = appinfo['profile']['policies'][0]['guid']
    # get policy using API
    return vapi().get_policy(policy_guid)

def getstaticscan(appinfo):
    scan_url = None
    scans = appinfo['scans']
    for scan in scans:
        if (scan['scan_type'] == 'STATIC'):
            if scan['status'] != 'PUBLISHED':
                return scan_url # don't try to get report for unpublished app
            scan_url = scan['scan_url']
    return scan_url

def parsescanurl(scan_url):
    parts = scan_url.split(":",6)
    build_id = parts[3]
    return build_id

def parse_and_remove_xml_namespaces(xml_string):
    if sys.version_info >= (3,):
        it = etree.iterparse(BytesIO(xml_string))
    else:
        it = etree.iterparse(StringIO(xml_string))
    for _, el in it:
        if "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]  # strip all namespaces
    return it.root

def getdetailedreport(build_id):
    detailedreport = vapi().get_detailed_report(build_id)
    detailedreport_root = parse_and_remove_xml_namespaces(detailedreport) #manipulating with ns is a pain
    return detailedreport_root

def getstaticanalysis(detailedreport_root):
    staticanalysislist = detailedreport_root.findall('static-analysis')
    return staticanalysislist[0]

def rightsize(detailedreport_root):
    staticanalysis = getstaticanalysis(detailedreport_root)
    if staticanalysis == None:
        return false
    analysissize = staticanalysis.get('analysis_size_bytes')
    return ( int(analysissize) <= constants.MAX_ANALYSIS_SIZE)

def getmodules(detailedreport_root):
    staticanalysis = getstaticanalysis(detailedreport_root)

    if staticanalysis == None:
        return None

    modulesall = staticanalysis.findall ('modules')
    modules = modulesall[0]

    modulelist = []
    for module in modules:
        # turn module into item in dictionary
        modulename = module.get('name')
        thismodule = {'name': module.get('name'), 'compiler': module.get('compiler'), 'os': module.get('os'), 'architecture' : module.get('architecture')}
        # validate that module is supported
        if not(rightlanguage(thismodule)):
            logging.debug("Module not supported:\r\nname: {}\r\ncompiler: {}\r\narchitecture: {}\r\n"
                    .format(thismodule.get("name"),thismodule.get("compiler"),thismodule.get("architecture")))
            continue
        modulelist.append(thismodule)

    return modulelist

def rightlanguage(module):
    return ( module.get("compiler") in constants.SUPPORTED_COMPILERS ) &\
          ( module.get("architecture") in constants.SUPPORTED_ARCH)

def writetemplate(appid,policy,report,modules):
    base_template = 'java -jar pipeline-scan.jar -f {modulename} -aid {app}'
    severity_template = ' -fs "{sev}"'
    cwe_template = " -fc {cwe}"

    #parse policy to get severity and cwe rules
    severities = getseverityrules(policy)
    cwes = getcwerules(policy)

    scripttemplate = []
    for module in modules:
        moduletemplate = base_template.format(modulename = module['name'], app = appid)
        if severities != []:
            severitylist = ', '.join(severities)
            severity = severity_template.format(sev = severitylist)
            moduletemplate = moduletemplate + severity

        if cwes != []:
            cwelist = ', '.join(cwes)
            cwe = cwe_template.format(cwe = cwelist)
            moduletemplate = moduletemplate + cwe

        scripttemplate.append(moduletemplate)

    f=open('pipeline_template.txt','w')
    s1='\n'.join(scripttemplate)
    f.write(s1)
    f.close()

    print("Wrote",len(scripttemplate),"template commands to pipeline_template.txt")
    return scripttemplate

def getseverityrules(policy):
    severities = []
    for rule in policy['finding_rules']:
        if (rule['type'] == "MAX_SEVERITY") & ("STATIC" in rule['scan_type']):
            severities.append(getseveritybynumber(rule['value']) )
    return severities

def getseveritybynumber(sevnumasstring):
    return constants.SEVERITIES.get(sevnumasstring) 

def getcwerules(policy):
    rules = policy['finding_rules']
    cwes = []
    cwe = ''
    for rule in rules:
        if (rule['type'] == "CWE") & ("STATIC" in rule['scan_type']):
            cwe = rule['value']

            cwes.append(cwe)
    return cwes

def main():
    parser = argparse.ArgumentParser(
        description='This script generates Pipeline Scan template command lines for the applications specified based on the uploaded modules and the policy in use.')
    parser.add_argument('-a', '--application', required=False, help='Application ID for the application for which you want a Pipeline Script template.',default="239510")
    args = parser.parse_args()

    appid = args.application

    logging.basicConfig(filename='vcpipelinescript.log',
                        format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S%p',
                        level=logging.INFO)

    # CHECK FOR CREDENTIALS EXPIRATION
    creds_expire_days_warning()

    # get application
    print("Getting information for application {}".format(appid))
    appinfo = getapplication(appid)
    if appinfo == None:
        print("Could not get information for application {}".format(appid))
        return

    app_message_name = "Application ID {} ({})".format(appid,appinfo['profile']['name'])

    print("Getting policy information for",app_message_name)
    apppolicy = getpolicy(appinfo)

    scan_url = getstaticscan(appinfo)
    if scan_url == None:
        print(app_message_name, "has no static scans that are published.")
        return

    # get latest build for application
    build_id = parsescanurl(scan_url)

    print("Found build_id {} for {}".format(build_id,app_message_name))

    # get detailed report to check module list for language and size?
    report = getdetailedreport(build_id)
    if not (rightsize(report)):
        print(app_message_name, 'is larger than the maximum size for Pipeline Scan.')
        return

    modules = getmodules(report)
    if (modules == []):
        print(app_message_name,"has no modules in a language supported by Pipeline Scan.")
        return

    # create template
    writetemplate(appid,apppolicy,report,modules)

if __name__ == '__main__':
    main()
import os
import sys
import json

sys.path.insert(0, os.getcwd())
from email_analyzer.analyzer import analyze_email
from email_analyzer.mail_reporter import MailReporter

sample_path = os.path.join('data', 'working', 'url_wrapper_check.eml')
with open(sample_path, 'w', encoding='utf-8') as fh:
    fh.write('From: tester@example.com\r\n')
    fh.write('To: analyst@example.com\r\n')
    fh.write('Subject: Wrapper test\r\n')
    fh.write('Content-Type: text/plain; charset=utf-8\r\n\r\n')
    fh.write('Please visit https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Flogin\r\n')

data = analyze_email(sample_path)
print('wrapped', data['urls_extracted_detail'][0]['wrapped'])
print('provider', data['urls_extracted_detail'][0]['provider'])
print('decoded', data['urls_extracted_detail'][0]['decoded_url'])
print('decode_success', data['urls_extracted_detail'][0]['decode_success'])
print('urls_sorted', data['urls_extracted'])
reporter = MailReporter(output_dir='reports')
path = reporter.generate_json_report(data)
with open(path, 'r', encoding='utf-8') as fh:
    report = json.load(fh)
print('json_report', os.path.basename(path))
print('wrapper_in_json', any(item.get('wrapped') for item in report['urls_extracted_detail']))

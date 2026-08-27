from django.shortcuts import render
from django.http import HttpResponse
from django.conf import settings
import os, re, json, hashlib, time, shutil, subprocess, threading

def nmap_scaninfo(request):
	tmpfiles = os.listdir('/tmp/')
	res = {'out':[], 'scans':{}}

	for ff in tmpfiles:
		if not ff.endswith('.active'):
			continue

		if ff.endswith('.xml.active'):
			f = ff[:-7]
		else:
			f = ff[:-6]

		res['scans'][f] = {'status':'active'}
		try:
			with open('/tmp/' + ff) as n:
				lines = n.readlines()
				for line in lines:
					line = line.strip()
					if not line:
						continue

					rx = re.search(r'args\s*=\s*["\']?[^"\']*-oX\s+/tmp/([^"\'\s]+)', line)
					if rx is not None:
						res['scans'][f]['filename'] = rx.group(1)

					rx = re.search(r'args\s*=\s*["\']?[^"\']*startstr\s*=\s*["\']?([^"\'>\s]+)', line)
					if rx is not None and 'startstr' in line:
						res['scans'][f]['startstr'] = rx.group(1)

					if 'startstr=' in line or 'startstr="' in line:
						m = re.search(r'startstr\s*=\s*["\']?([^"\'\s>]+)', line)
						if m is not None:
							res['scans'][f]['startstr'] = m.group(1)

					rx = re.search(r'scaninfo type\s*=\s*["\']?(.+?)["\']?\s+protocol\s*=\s*["\']?(.+?)["\']?\s+numservices', line)
					if rx is not None:
						res['scans'][f]['type'] = rx.group(1)
						res['scans'][f]['protocol'] = rx.group(2)

					rx = re.search(r'finished .+?summary\s*=\s*["\']?(.+?)["\']?\s+exit\s*=', line)
					if rx is not None:
						res['scans'][f]['status'] = 'finished'
						res['scans'][f]['summary'] = rx.group(1)

						try:
							src = '/tmp/' + ff
							dst = '/opt/xml/' + f
							if os.path.exists(src):
								shutil.move(src, dst)
						except Exception:
							pass
		except Exception:
			pass

	return HttpResponse(json.dumps(res, indent=4), content_type="application/json")

def nmap_newscan(request):
	if request.method == "POST":
		filename = request.POST.get('filename', '').strip()
		if not filename:
			filename = 'webmap_scan_' + str(int(time.time())) + '.xml'

		params = request.POST['params'].strip()
		target = request.POST['target'].strip()

		if(re.search(r'^[a-zA-Z0-9\_\-\.]+$', filename) and re.search(r'^[a-zA-Z0-9\-\.\:\=\s,]+$', params) and re.search(r'^[a-zA-Z0-9\-\.\:\/\s]+$', target)):
			res = {'p':request.POST}

			# Ensure we use absolute path for nmap if possible, or assume it's in PATH.
			nmap_bin = 'nmap'
			if os.path.exists('/usr/bin/nmap'):
				nmap_bin = '/usr/bin/nmap'
			elif os.path.exists('/usr/local/bin/nmap'):
				nmap_bin = '/usr/local/bin/nmap'

			# Build a safe argument list instead of using shell=True.
			cmd_args = [nmap_bin] + params.split() + ['--script=' + os.path.join(settings.BASE_DIR, 'nmapreport', 'nmap', 'nse', '')] + ['-oX', '/tmp/' + filename + '.active'] + target.split()
			log_file = '/tmp/nmap_scan.log'
			active_file = '/tmp/' + filename + '.active'
			final_file = '/opt/xml/' + filename

			def run_scan_async(args, stdout_path, active_path, dest_path):
				with open(stdout_path, 'ab') as logfd:
					proc = subprocess.Popen(args, stdout=logfd, stderr=subprocess.STDOUT)
					proc.wait()
				try:
					shutil.move(active_path, dest_path)
				except Exception as e:
					print('Failed to move nmap output file:', e)

			# Launch the scan in a background thread without shell interpolation.
			threading.Thread(target=run_scan_async, args=(cmd_args, log_file, active_file, final_file), daemon=True).start()

			if request.POST['schedule'] == "true":
				schedobj = {'params':request.POST, 'lastrun':time.time(), 'number':0}
				filenamemd5 = hashlib.md5(str(filename).encode('utf-8')).hexdigest()
				writefile = '/opt/schedule/'+filenamemd5+'.json'
				file = open(writefile, "w")
				file.write(json.dumps(schedobj, indent=4))

			return HttpResponse(json.dumps(res, indent=4), content_type="application/json")
		else:
			res = {'error':'invalid syntax'}
			return HttpResponse(json.dumps(res, indent=4), content_type="application/json")

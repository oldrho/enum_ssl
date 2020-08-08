#!/usr/bin/env python3

import socket, ssl
import OpenSSL
import argparse
import sys

def download(hostname, port, ip=False):
	if not ip:
		ip = hostname

	context = ssl.SSLContext()
	context.verify_mode = ssl.CERT_NONE

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ssl_sock = context.wrap_socket(s, server_hostname=hostname)

	try:
		ssl_sock.connect((ip, port))
	except OSError:
		sys.stderr.write("Could not connect to %s:%s\n" % (ip, port))
		return False

	cert = ssl.DER_cert_to_PEM_cert(ssl_sock.getpeercert(True))
	ssl_sock.close()

	return cert


def get_hostnames(cert):
	hosts = []
	x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

	# Subject Name
	subject = x509.get_subject().get_components()
	for (name,val) in subject:
		if name == b'CN':
			hosts += [val.decode('utf-8')]

	# Subject Alternative Names
	ext_count = x509.get_extension_count()
	for i in range(0, ext_count):
		ext = x509.get_extension(i)
		if b'subjectAltName' == ext.get_short_name():
			line = str(ext)
			hosts += line.replace('DNS:', '').replace(',', '').split(' ')
	
	hosts = list(dict.fromkeys(hosts))
	return hosts


def main():
	parser = argparse.ArgumentParser(description='Download and parse SSL certificates from servers')
	
	parser.add_argument('hostname', nargs='?', help='Hostname or IP of the target server')
	parser.add_argument('port', nargs='?', type=int, default=443, help='Port number')
	parser.add_argument('-f', '--file', help='Load PEM encoded certificate from a file')
	parser.add_argument('-i', '--ip', help='IP to connect to (can be different than the hostname)')
	parser.add_argument('-o', '--writefile', default=None, help='Write certificate to file')

	args = parser.parse_args()
	cert = None

	# Open certificate from a file
	if args.file:
		try:
			with open(args.file, 'r') as file:
				cert = file.read()
				file.close()
		except OSError:
			sys.stderr.write("Could not open %s\n" %(args.file))
			cert = False

	# Download certificate from an SSL server
	elif args.hostname:
		if not args.ip:
			args.ip = args.hostname

		cert = download(args.hostname, args.port, args.ip)

		if cert and args.writefile:
			with open(args.writefile, 'w') as file:
				file.write(cert)
				file.close()


	if cert is False:
		return

	if not cert:
		sys.stderr.write("No certificate loaded\n")
		return

	# Parser hostnames
	hosts = get_hostnames(cert)

	print("\n".join(hosts))


if __name__ == '__main__':
	main()

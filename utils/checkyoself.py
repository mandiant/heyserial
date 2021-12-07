# Copyright (C) 2021 Alyssa Rahman, Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

TITLE           = """   ________              __      __  __                ______
  / ____/ /_  ___  _____/ /__    \ \/ /___  ________  / / __/
 / /   / __ \/ _ \/ ___/ //_/     \  / __ \/ ___/ _ \/ / /
/ /___/ / / /  __/ /__/ ,<        / / /_/ (__  )  __/ / __/
\____/_/ /_/\___/\___/_/|_|      /_/\____/____/\___/_/_/"""
AUTHOR          = "Alyssa Rahman (@ramen0x3f)"
LASTUPDATED     = "2021-12-02"
DESCRIPTION     = "Check Yoself Before You Wreck Yo....Network."

USAGE        = "python3 checkyoself.py [-y rules.yara] [-s rules.snort] [-o file_output_prefix] [--matches] [--misses] -d malware.exe malware.pcap"
EXAMPLES	= "python3 checkyoself.py -y rules/javaobj -s rules/javaobj -d payloads/javaobj pcaps --misses -o java_misses"

from argparse import ArgumentParser,RawTextHelpFormatter
from io import TextIOWrapper
from magic import from_file as magic_from_file
from pathlib import Path
from subprocess import PIPE,run
from sys import stdout
from yara import compile,SyntaxError,TimeoutError

def parse_arguments():
	"""Parse arguments from user

	Output
	------
	Success : ArgumentParser object
	Error : Exit program
	"""
	# Setting up argparser
	parser = ArgumentParser(description="{}\nBy: {}\tLast Updated: {}\n\n{}".format(TITLE, AUTHOR, LASTUPDATED, DESCRIPTION),
				formatter_class=RawTextHelpFormatter, epilog="examples: \n{}".format(USAGE))
	parser.add_argument('-y', '--yara', nargs="+", required=False,
				help='path to files or directories with yara rules to use. Requires .yara extension.')
	parser.add_argument('-s', '--snort', nargs="+", required=False,
				help='path to files or directories with snort rules to use. Requires .snort extension.')
	parser.add_argument('-d', '--data', nargs="+", required=True,
				help='path to files or directories to scan')
	parser.add_argument('-o', '--output', required=False,
				help='filename to output results to. _[ruletype].tsv will be appended. default: print to screen')
	parser.add_argument('--matches', action='store_true',
				help='ony show files (yara) or rules (snort) that have at least one match in output. default: false.')
	parser.add_argument('--misses', action='store_true',
				help='only show files (yara) or rules (snort) that have 0 matches in output. default: false.')
	args = parser.parse_args()

	# Data, data, data! I cannot make bricks without clay!
	if args.yara is None and args.snort is None:
		print("[!] ERROR - No Snort or Yara rules provided. Run with -h to see full help.")
		exit()

	# #NoFilter
	if args.matches and args.misses:
		print("[!] ERROR - Nice try, pal. You can't have only matches AND only misses.")
		exit()

	# Parse and print all choices
	yara_pretty = "\n\t\t".join(args.yara) if args.yara else "None provided."
	snort_pretty = "\n\t\t".join(args.snort) if args.snort else "None provided."
	data_pretty = "\n\t\t".join(args.data)

	print("[+] {}\n\tYara Rules\n\t\t{}\n\tSnort Rules\n\t\t{}\n\tData\n\t\t{}"\
		.format(DESCRIPTION, yara_pretty, snort_pretty, data_pretty))

	return vars(args)

def get_files(path_input, filetype):
	"""Get file objects for provided paths

	Input
	-----
	path_input : list of str
	filetype : str
		yara, snort, data

	Output
	-----
	Success :
		data = List of Path objects for provided inputs
		yara/snort = String with rule content
	Error : None
	"""
	# Set up
	isrule = True if filetype in ['snort', 'yara'] else False
	f_ext = "*{}".format(filetype) if isrule else "*"
	pi_list = [Path(p) for p in path_input]
	f_list = []

	# From the top
	for p in pi_list:
		# Womp womp ya done goofed
		if not p.exists():
			print("[!] WARNING: {} file {} does not exist. Skipping.".format(filetype, p))

		# Director(ies) cut
		elif p.is_dir():
			f_list.extend([str(x.resolve()) for x in list(p.glob('{}'.format(f_ext))) if x.is_file() and x not in f_list])

		# File cabinet
		elif p.is_file():
			# Need the right file extension if snort or yara
			if p.suffix[1:] == filetype or not isrule:
				f_list.append(str(p.resolve()))

		# Just in case
		else:
			print("[!] WARNING: It's not a directory or a file...not sure what happened? {}".format(p))

	if filetype == "yara":
		rule_content = ""
		for f in f_list:
			with open(f, 'r') as rule:
				rule_content = "{}\n{}".format(rule_content, rule.read())
		return rule_content
	else:
		return f_list

def check_yara(rules, filter, data):
	"""Check all provided Yara rules and pretty print results

	Input
	-----
	rules : list of strings
		file/dir paths provided by user with Yara rules
		only cares about .yara extensions
	filter : string
		either "miss", "match", or "missmatch"
	data : list of strings
		absolute file paths from get_files()

	Output
	------
	Success : string
		TSV output of all results for printing
	Error : None
	"""
	# Load up the Yara cannons
	try:
		yara = compile(source=get_files(rules, "yara"))
		output = "Data file\tYara Matches"
	except SyntaxError as s:
		print("[!] ERROR: Syntax error in your Yara rules. Please review.")
		return None

	# Aaaaand fire!
	for d in data:
		try:
			yara_result = ", ".join([m.rule for m in yara.match(d, timeout=10)])
			yara_status = "miss" if len(yara_result) == 0 else "match"

			if yara_status in filter:
				output = "{}\n{}\t{}".format(output, d, yara_result)
		except TimeoutError:
			print("[*] WARNING: {} took too long to scan. Skipping.".format(d))

	return output

def check_snort(rules, filter, data):
	"""Check all provided Snort rules and pretty print results

	Input
	-----
	rules : list of strings
		file/dir paths provided by user with Snort rules
		only cares about .snort extensions
	filter : string
		either "miss", "match", or "missmatch"
	data : list of strings
		absolute file paths from get_files()

	Output
	------
	Success : string
		TSV output of all results for printing
	Error : None
	"""

	# Load up the Snort cannons
	snort = get_files(rules, "snort")
	output = "Snort Rule\t# Matches\n"
	data_pcaps = " -r ".join([d for d in data if "pcap" == magic_from_file(d)[0:4]])
	args = ["snort", "-N", "-q", "-A", "console", "-k", "none", "-r", data_pcaps, "-c"]
	snort_counts = {}

	if snort is None:
		return None

	# Leggooo
	for s in snort:
		proc = run(args + [s], capture_output=True) #Run single snort file against all pcaps

		if proc.stderr: #Something went wrong
			print("[!] ERROR Could not test {}. Check for Snort errors.".format(s))
			print(proc.stderr)
			continue

		snort_result = proc.stdout.decode('utf-8') #Get list of alerts from snort
		snort_status = "miss" if len(snort_result) == 0 or "  [**] [" not in snort_result else "match"

		# Print if relevant
		if snort_status in filter:
			# If it's a miss, use the Snort file name
			if snort_status == "miss":
				output = "{}{}\t**No Snort Matches**\n".format(output,s)

			# Build up dictionary of hit counts for each rule (dif than .snort files)
			for sr in snort_result.split("\n")[0:-1]:
				try:
					sig = sr.split(" [**] ")[1].split(" ")[1]
					if sig in snort_counts:
						snort_counts[sig] += 1
					else:
						snort_counts[sig] = 1

				except:
					continue
	return output[:-1] + "\n".join(["{}\t{}".format(sig, count) for sig,count in snort_counts.items()]) #output[:-1] strips last \n

if __name__ == "__main__":
	"""Main function

	Run with python3 checkyoself.py -h for full details
	"""
	# Set up arguments and figure out what we're testing
	args = parse_arguments()
	rule_types = {
		"yara": { "test": check_yara, "output": None if args['yara'] is None else stdout},
		"snort": { "test": check_snort, "output":  None if args['snort'] is None else stdout}
	}

	# Don't need to account for if args.matches && args.misses, since argparser will stop that.
	if args['matches']:
		filter = "match"
	elif args['misses']:
		filter = "miss"
	else:
		filter = "missmatch"

	# No malware mo problems
	data = get_files(args['data'], "data") if args['data'] is not None else None
	if data is None:
		print("[!] ERROR: No data files found to scan from provided paths.")
		exit()

	# Pencils down - time to check the tests!
	for k,v in rule_types.items():

		if v['output'] is None: #No rules provided for this format
			continue

		print("[+] Testing {} rules...".format(k))

		# Create files if needed
		if args['output']:
			filename = "{}_{}.tsv".format(args['output'], k)
			if Path(filename).exists():
				print("[*] WARNING: {} output file already exists. Printing to screen instead.".format(k))
			else:
				rule_types[k]['output'] = open(filename, 'w')

		# Call test function and print output
		result = v['test'](args[k], filter, data)
		if result is not None:
			print(result, file=v['output'])
		else:
			print("[*] ERROR: No test results to print for {}".format(k))

		# Clean up
		if isinstance(v['output'], TextIOWrapper) and v['output'] is not stdout:
			v['output'].close()

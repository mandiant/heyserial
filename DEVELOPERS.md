# Contributing 
**Found a bug?** 
Create an Issue on this repo. (Disclaimer: No promises on if/how soon I'll push fixes.)

**Added something cool?**
Nice work!! Teamwork makes the dream work, so create a pull request.

**Wanna figure out _how_ to add something cool?**
You're in the right spot! Keep reading...

# Adding New Things
Adding a new object type only requires updating the `object_types` global list. See "Object Types" below for more details. 

Adding a new encoder or rule format is a simple 2 step process.
1. Create your function 
2. Add it as an accepted argument

The "Encoders" and "Output/Rule Types" sections below include templates for the different function types. After creating one, add a key/value pair with your new function(s) to the `encoding_types` or `output_types` global lists. 

Please note the keys you add to these global lists will be what you provide as an argument to HeySerial (like -o yara or -e base64), and they are **case sensitive**.

## Object Types
To add an object type, you simply need to add a key/value pair to the `object_types` global list. 

```"<INSERT>": {"raw": "<INSERT>"}```

The key will be the object name to use as a parameter. For example: JavaObj, PythonPickle, etc.

The value will be a dictionary with an initial "raw" key and a string with `\x` formatted bytes to search for as an object header/prefix. 

As a note of one exception to this rule: for PHP Objects, the prefix is `O:[0-9]+:`. I used O: as the prefix, and to keep the conditions more strict I modified the build_regex() function to manually add a regex for [0-9] in both ASCII/raw and Base64 encodings. Other encodings (such as UTF16), will require further manual modification. 

## Encoders
To add an encoder, you'll need to 1. Create your function 2. Add it as an accepted argument. 

1. Create a function using the template below and modify the portions labeled <INSERT>. 
  
```
def enc_<INSERT>(term, isprefix=False):
	"""Encode provided term as <INSERT>
	Parameters
	----------
	term : byte string
		keyword or object prefix to be encoded
	isprefix : bool, optional
		specify if it's a keyword or object prefix, by default False
	Output
	------
	encoded term value: list of byte strings
		if isprefix==False
	encoded prefix value : byte string
		if isprefix==True
	"""
  
  decoded_term = term.decode(detect(term)['encoding']) #You may want to decode it cleanly first
  encoded_term = <INSERT> #use decoded_term 
  
	return encoded_term if isprefix else [encoded_term]
```

2. Add your function as an accepted argument by adding a key/value pair like: `"<INSERT>": enc_<INSERT>` to the `encoding_types` global list. 

Notes: 
* The key will be what you provide as an argument (like -e base64), and it is **case sensitive**.
* The value must exactly match your function name. **Do not add parentheses**. 

## Output / Rule Types
To add an object/rule type, you'll need to 1. Create your function 2. Add it as an accepted argument. 

1. Create a function using the template below and modify the portions labeled <INSERT>. 
  
```
def gen_<INSERT>(searchterm, keywords, objtype, objheader, encoding, ischain=False):
	"""Generate <INSERT> rule for provided searchterm+object type+encoding
	
  Parameters
	----------
	searchterm : ASCII string
		original user-provided input
	keywords : dictionary <keyword>:list_of_encoded_versions
		dictionary of all keywords and a list of their encoded versions
		some methods (e.g. Base64 offsets) may have multiple values
		if ischain==True, this list will include all individual keywords from the chain.
	objtype : ASCII string
		must be one of supported types
	objheader : ASCII string
		prefix. may be encoded. some prefixes/encodings require special modifications.
	encoding : ASCII string
		name of encoding method
	ischain : bool, optional
		specify if it's a + delimited chain, by default False
	
  Output
	------
	Success : (string, string)
		name and rule
	Error : None
	"""

try:
		name = "<INSERT>".format(objtype, prep_for_name(searchterm,ischain), prep_for_name(encoding))
		regpattern = build_regex(searchterm, keywords, objtype, objheader, ischain)
		rule = "<INSERT>".format(name, prep_for_name(searchterm), objheader, regpattern)
		return name, rule
	
  except Exception as e:
		print("[!] ERROR - Something went wrong trying to create a <INSERT> rule for {}".format("+".join(searchterm) if ischain else searchterm))
		print(e)
		return None
```

2. Add your function as an accepted argument by adding a key/value pair like: `"<INSERT>": gen_<INSERT>` to the `output_types` global list. 

Notes: 
* The key will be what you provide as an argument (like -o yara), and it is **case sensitive**.
* The value must exactly match your function name. **Do not add parentheses**. 

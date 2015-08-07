## USNeasy an Ubuntu Security Notice parser in perl.

### Why?
################################################################################
Every time a security notice comes in, I go through the same routine: Skim the
notice, determine if it's a remote or local vuln, script up something in bash
or puppet to determine if any of my systems have the vulnerable packages
installed, set up a patch schedule, and crank through the patching.

It's all far too manual. There are gui tools in ubuntu that tell me when my
systems need patching, but I wanted something I could put into a nagios check.

The security notices are pretty formulaic. So it seemed like a trivial task to
parse them and coerce them into JSON. So that's what I did.


### Usage
1) Fetch the Security Notices from lists.ubuntu.com *(note: you might want to delete the current <year>-<month>.txt as it won't re-download it if it exists, and it is still getting appended on remote)*

```
rm data/$(date +"%Y-%B").txt
bin/fetch
```

2) Parse the Security Notices now in ./data and create the json files in ./output
```
bin/parse data
```

3) Run the nagios check that will scan the json files in ./output and compare them to the local system
```
*WIP*
```

### Erratta
It will bypass the older format USNs, (pre-2011) as they were not in the same format and I don't have a lot of reason to scan distributions from that far back.

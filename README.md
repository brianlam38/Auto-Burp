## Burp Automation - standalone
The program `autoburp.py` is a standalone Burp Automation tool.

Requirements
* VMWare's Burp Rest API: `https://github.com/vmware/burp-rest-api`
* Burp Suite Professional: `https://portswigger.net/burp`

Usage
1. Set up VMWare's Burp Rest API service.
2. `autoburp.py [ url ]` to run the scan.

## Burp Automation - StackStorm
The program `autoburp_action.py` is a StackStorm action script, used only in the context of a StackStorm workflow.
See more at `https://docs.stackstorm.com/`.

Requirements
* StackStorm: `https://stackstorm.com/`
* VMWare's Burp Rest API: `https://github.com/vmware/burp-rest-api`
* Burp Suite Professional: `https://portswigger.net/burp`

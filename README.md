# Automation-PowerShell
F5 Automation Playbook with PowerShell
There are a lot of resources regarding automation with F5 tools AS3 and DO, but
none of them really address doing this from PowerShell which is typically not
used as much as alternatives.  This playbook is meant to be a set of examples
on taking an F5 from "just a mgmt IP" to a configured endpoint using these
tools with PowerShell.

The code is NOT optimized and there is a lot of redundant code here, this is
purposeful.  The idea is that you could copy and paste any of these steps and
easily integrate it into an existing code base/workflow.  This CAN be run
with the requisite resources as well, but some refactoring and cleanup would
yield much more maintainable code.

This code is presented AS-IS with no warranty or support implied or otherwise 
and provided entirely free.
 
Requires PS 7.x or >
Elements borrowed from here:  https://github.com/mjmenger/terraform-bigip-postbuild-config/blob/main/atcscript.tmpl

Requires DO and AS3 RPMs.  These can be found here:
* AS3 Releases:  https://github.com/f5networks/f5-appsvcs-extension/releases
* DO Releases:   https://github.com/F5Networks/f5-declarative-onboarding/releases

Ensure that the references to in the playbook to RPMs match the filenames/versions you download.  It is also advisable that you update the $schema reference at the top of the script.


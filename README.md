This code built and run on Intel P4Studio SDE environment (mimicing Tofino ASIC), acts as a FIREWALL and it consists of P4 source code that demonstrates the following (in a Programmable Data Plane).
1. How to perform payload inspection (DPI).
2. Iterating string, character by character using the technique of RECIRCULATE-AND-TRUNCATE.
3. Match actions
4.   ACCEPT --> When character/string matched.
5.   REJECT --> When character/string not matched.

6.   Example:
7.   If a host tried to access a forbidden URL, say, www.forbidden.com,
8.     Code iterates through it and if there is a match, host fails to access it. Allows the URL to go through the ASIC/Model if it is whitelisted.

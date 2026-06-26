**Basilisk**

Basilisk is a cybersecurity tool intended for ethical/licensed hackers to test networks, view vulnerabilities and lookup names, Basilisk isnt designed to cause harm.
The Basilisk team isnt responsible for what you do with the Basilisk tool, so keep that in mind.

Before compiling it, you need the following pieces of software:

          curl nlohmann-json whois

Download them from your console:
Windows:

          winget install curl nlohmann-json whois

MacOS:

          brew install curl nlohmann-json whois

Linux(deb):

          sudo apt install curl nlohmann-json whois

Linux(arch):

          sudo pacman -S curl nlohmann-json whois

Or search up how to install them for your operating system

To compile the *Basilisk tool* you have to first get the basilisk.cpp file from https://github.com/raulcode-sys/Basilisk-Ethical-Hacking-Tool, and then compile it with:

          g++ -std=c++11 -O3 -o basilisk basilisk.cpp -lpthread -lcurl

then run:

          ./basilisk

and you got the *Basilisk* tool running!


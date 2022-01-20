# shitty-driver-dumper
Very low effort application that dumps a driver. Doesn't fix the dump and doesn't unmap itself. I have an unusually low IQ so sorry. 

WINDOWS ONLY!!!!!!!

Ok so basically in main.cpp you gotta change 2 strings, one with the path you want your dump to be stored at and one with the name of the driver (without the path). Then manual map it with a tool like kdmapper and as soon as the target driver is detected it will be dumped. This is useful for things like BEDaisy.sys or EasyAntiCheat.sys that won't be running until the game is started. Then you should restart to get rid of the driver. You don't have to as it won't be executing any more code but it gives me ocd to know my kernel has garbage in it.

@load base/frameworks/intel
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice

redef Intel::read_files += {
	"/opt/Vetted/clients/Vetted_Bro_Client/vetted_intel.dat"
};

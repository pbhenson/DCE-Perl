use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

WriteMakefile(
     TYPEMAPS => '../typemap',	       
    'NAME'	=> 'DCE::attrbase',
    'VERSION_FROM' => 'attrbase.pm', # finds $VERSION
);

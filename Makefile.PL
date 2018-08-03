=pod

According to Paul B. Henson <henson@acm.org>:

The correct configuration for Solaris is to compile DCE-perl with *only*
-ldce, and then recompile perl itself including at least the following
libraries:

-ldce -lsocket -lnsl -lthread -lm


FYI, for Digital Unix 4.0, you only need '-ldce'.

For Digital Unix 3.2, you need '-ldce -lpthreads -lmach -lc_r'.

=cut

use Config; 
use ExtUtils::MakeMaker;
use strict;
my $def_dce_libs = '-L/usr/include/dce -ldce';

my $mm_dce = {
    hpux => {LIBS => [$def_dce_libs, "-lc_r"]},
    solaris => {LIBS => [qw(-ldce -lnsl -lthread -lm)],
		DEFINE => '-D_REENTRANT',
		FULLPERL => '/usr/local/bin/dceperl',
		PERL => '/usr/local/bin/dceperl'}
};
  
# Provide a default LIBS for other systems.
my $MM_dce = $mm_dce->{$Config{osname}} || {LIBS => [$def_dce_libs]};
  
my $typemap = '../typemap';
if (!-f $typemap) { $typemap = './typemap'; } # for top level

WriteMakefile (
  %$MM_dce,
  TYPEMAPS => [$typemap],
  XSPROTOARG	=> '-noprototypes',
  NAME => 'DCE-Perl',
  VERSION => '0.15',
  'dist'    => {
      COMPRESS=> 'gzip -9f', SUFFIX=>'gz', 
      POSTOP => 'mv $(DISTNAME)-$(VERSION).tar.gz ../',
  },
);

#    "\t".'XSUBPPARGS="$(XSUBPPARGS) -typemap ../typemap"\\', 
#    "\t".'XSUBPPDEPS="$(XSUBPPDEPS) ../typemap"\\', 
sub MY::pasthru {
    my $self = shift;
    chomp(my $str = $self->MM::pasthru);
    join $/, "$str\\", 
    "\t".'DEFINE="$(DEFINE)"\\', 
    "\t".'PERL="$(PERL)"\\', 
    "\t".'FULLPERL="$(FULLPERL)"\\', 
    "\t".'EXTRALIBS="$(EXTRALIBS)"\\', 
    "\t".'LDLOADLIBS="$(LDLOADLIBS)"\\', 
    "\t".'XSPROTOARG="$(XSPROTOARG)"', 
    "";   
}

sub MY::test {
    q(
TEST_VERBOSE=0

test:
	$(FULLPERL) t/TEST $(TEST_VERBOSE)

);
}

sub MY::post_initialize {
    my($self) = shift;
    # handy for other DCEish .xs modules 
    $self->{PM}->{'DCE_Perl.h'} = '$(INST_ARCHLIBDIR)/DCE/DCE_Perl.h';
    '';
}

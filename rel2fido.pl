sub checkecho
{
  if (index($area, "kiev.fido.") >= 0 || index($area, "ukr.fido.") >= 0)
  {
    return 4 if $size>48*1024;
  }

  if (index($intsetname, "cp866") >= 0)
  {
    if (($body =~ tr/÷öùøõôóò//) > 0)
    { $intsetname = "cp866-u";
    } else
    { $intsetname = "cp866";
    }
  }

  return 1;
}

sub checknetmail
{
  @bounce = qw (
	@p13.f520.z2.
	@p77.f574.z2.
	f128.n46.z2.
	@p11.f1.n4614.z2.
	@p12.f1.n4614.z2.
	@p12.f733.n463.z2.
	@p52.f12.n460.z2.
	@p380.f455.n463.z2.
	@p220.f455.n463.z2.
  );

  @devnull = qw (
	@f598.n463.z2.
	@p0.f598.n463.z2.
	@p909.f463.n463.z2.
	@p4.f1.n4631.z2.
	@p50.f1.n4641.z2.
	@p15.f287.n463.z2.
	f69.n463.z2.
	@p39.f1.n466.z2.
	f463.n463.z2.
	@p32.f11.n463.z2.
	@p777.f11.n463.z2.
	f78.n463.z2.
	@p27.f2213.n4642.z2.
	f1504.n5020.z2.
	@p2.f2.n4633.z2.
	@p9000.f275.n463.z2.
	@f434.n463.z2.
	volodya.danchenko@p240.f131.n463.z2.fidonet.org
  );

  $to =~ tr/A-Z/a-z/;
  foreach (@bounce)
  {
	return 5 if index($to, $_)>=0;
  }
  foreach (@devnull)
  {
	return 4 if index($to, $_)>=0;
  }

  if (index($intsetname, "cp866") >= 0)
  {
    if (($body =~ tr/÷öùøõôóò//) > 0)
    { $intsetname = "cp866-u";
    } else
    { $intsetname = "cp866";
    }
  }

  return 1;
}

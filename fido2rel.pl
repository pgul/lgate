sub setcharset
{
  if (index($extsetname, "koi8") >= 0)
  {
    $subjbody = $subj . $body;
    if (($subjbody =~ tr/ùø÷öõôóò//) > 0)
    { $extsetname = "koi8-u";
    } elsif (($subjbody =~ tr/\x80-\xFF//) > 0)
    { $extsetname = "koi8-r";
    } else
    { $extsetname = "us-ascii";
    }
  }
  return 1;
}

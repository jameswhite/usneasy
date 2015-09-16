package USNEasy;
use strict;
# use warnings;

sub new{
  my $class = shift;
  my $usn = shift;
  my $self = {};
  $self->{'debug'} = 0;
  $self->{'notice'} = $usn;
  $self->{'severity'} = 0x0;
  $self->{'begins_with'} = {
                             'header'              => '^=+$',
                             'affects'             => '^(A security issue affects these releases of Ubuntu and its derivatives|A security issue affects the following Ubuntu releases):',
                             'summary'             => '^(Summary):',
                             'description'         => '^(Software Description):',
                             'details'             => '^(Details|Details (F|f)ollow):',
                             'update_instructions' => '^(Update (I|i)nstructions):',
                             'references'          => '^(References):',
                             'package_information' => '^(Package Information):',
                             'next_part'           => '^-+ next part -+$',
                           };

  bless $self, $class;
  return $self;
}

sub any_section_header{
  my $self = shift;
  my @regexes;
  foreach my $key (sort(keys(%{$self->{'begins_with'}}))){
    push(@regexes,$self->{'begins_with'}->{$key});
  }
  return "(".join('|',@regexes).")";
}

sub notice{
  my $self = shift;
  $self->{'notice'} = shift if @_;
  return $self->{'notice'};
}

# A section will be defined as the section header, until the start of any next section.
sub section{
  my $self = shift;
  my $type = shift;
  return $self->{$type} if defined($self->{$type});
  return undef unless(defined($self->{'begins_with'}->{$type}));
  my $in_section=0;
  my $has_section=0;
  my $section=[];
  my $stop_regex = $self->any_section_header;
  foreach my $line (split/\n/,$self->notice){
      if($line=~m/$self->{'begins_with'}->{$type}/){
         if ($in_section==0){
             $has_section=1;
             $in_section = 1;
         }else{
             $in_section = 0;
         }
      }elsif($line=~m/$stop_regex/){
        $in_section = 0 if ($in_section==1);
      }
      if($in_section == 1){
        if($in_section == 1){
           push(@{$section},$line) unless( ($type == 'header') && ($line=~m/$self->{'begins_with'}->{$type}/) );
        }
        if($self->{'debug'} > 0){
          if( ($type == 'header') && ($line=~m/$self->{'begins_with'}->{$type}/) ){
            print ":OUT: ".$line."\n";
          }else{
            print ": IN: ".$line."\n";
          }
        }
      }else{
        print ":OUT: ".$line."\n" if $self->{'debug'} > 0;
      }

  }
  return undef unless $has_section;
  $self->{$type} = join("\n",@{$section});
  return $self->{$type};
}

sub header{              my $self=shift; return $self->section('header');              }
sub affects{             my $self=shift; return $self->section('affects');             }
sub summary{             my $self=shift; return $self->section('summary');             }
sub description{         my $self=shift; return $self->section('description');         }
sub details{             my $self=shift; return $self->section('details');             }
sub update_instructions{ my $self=shift; return $self->section('update_instructions'); }
sub references{          my $self=shift; return $self->section('references');          }
sub package_information{ my $self=shift; return $self->section('package_information'); }
sub next_part{           my $self=shift; return $self->section('next_part');           }

sub has_header{              my $self=shift; return 1 if defined($self->header);              return 0; }
sub has_affects{             my $self=shift; return 1 if defined($self->affects);             return 0; }
sub has_summary{             my $self=shift; return 1 if defined($self->summary);             return 0; }
sub has_description{         my $self=shift; return 1 if defined($self->description);         return 0; }
sub has_details{             my $self=shift; return 1 if defined($self->details);             return 0; }
sub has_update_instructions{ my $self=shift; return 1 if defined($self->update_instructions); return 0; }
sub has_references{          my $self=shift; return 1 if defined($self->references);          return 0; }
sub has_package_information{ my $self=shift; return 1 if defined($self->package_information); return 0; }
sub has_next_part{           my $self=shift; return 1 if defined($self->next_part);           return 0; }

sub header_info{
  my $self=shift;
  return undef unless $self->has_header;
  my $header_line = join(' ',split(/\n/,$self->header));
  if($header_line=~m/((January|February|March|April|May|June|July|August|September|October|November|December) ([0-9]{1,2}), ([0-9]{4}))/){
    $self->{'date'}  = $1;
    $self->{'month'} = $2;
    $self->{'day'}   = $3;
    $self->{'year'}  = $4;
  }
  $header_line=~s/$self->{'date'}//;
  if($header_line=~m/(Ubuntu Security Notice ([^\s]+))/){
    $self->{'usn_text'}  = $1;
    $self->{'usn'}  = $2;

  }
  $header_line=~s/$self->{'usn_text'}//;
  $header_line=~s/^\s+//;
  $header_line=~s/\s+$//;
  $self->{'tagline'}=$header_line;
  return $self;
}

sub header_date{
  my $self = shift;
  return $self->{'date'} if defined $self->{'date'};
  $self->header_info;
  return $self->{'date'};
}

sub header_usn{
  my $self = shift;
  return $self->{'usn'} if defined $self->{'usn'};
  $self->header_info;
  return $self->{'usn'};
}

sub header_tagline{
  my $self = shift;
  return $self->{'tagline'} if defined $self->{'tagline'};
  $self->header_info;
  return $self->{'tagline'};
}

sub instructions{
  my $self=shift;
  return undef unless $self->has_update_instructions;
  my @instructions = split(/\n/,$self->update_instructions);
  my $in_packages=0;
  my $packages={};
  my @special_instructions;
  my $distro;
  while($#instructions > -1){
    my $line = shift(@instructions);
    if($in_packages == 1){
        if($line=~m/^((Ubuntu)\s+([^:]*):*)/){
          $distro = $3;
          $distro=~s/ LTS$//;
        }elsif($line=~m/^  (\S+)\s+(\S+)/){
          push(@{ $packages->{$distro} }, {'package' => $1, 'version' => $2});
        }elsif($line=~/^\s*$/){
          next;
        }else{
           $in_packages = 0;
           push(@special_instructions,$line) unless($line=~m/^\s*$/);
        }
     }else{
        if($line =~m/The problem can be corrected by updating your system to the following/){
          $line = $line." ".shift(@instructions);
          if($line =~m/The problem can be corrected by updating your system to the following package versions:/){
            $in_packages=1;
          }
        }
        push(@special_instructions,$line) unless($line=~m/^\s*$/);
     }
  }
  $self->{'package_updates'}=$packages;
  $self->{'special_instructions'}=join("\n",@special_instructions);
}

sub package_updates{
  my $self=shift;
  $self->instructions unless( defined($self->{'package_updates'}) );
  return $self->{'package_updates'};
}

sub special_instructions{
  my $self=shift;
  $self->instructions unless( defined($self->{'special_instructions'}) );
  return $self->{'special_instructions'};
}

sub cves{
  my $self = shift;
  my $references = $self->references;
  @{$self->{'cves'}} = $references=~/([Cc][Vv][Ee]-[0-9]+-[0-9]+)/g;
  return $self->{'cves'};
}

sub detail_breakdown{
  my $self = shift;
  $self->{'details'} = $self->details unless defined($self->{'details'});
  my @lines = split(/\n/,$self->{'details'});
  my $paragraphs = [];
  my $paraglines = [];
  foreach my $line (@lines){
    if($line=~m/^\s*$/g){
      if($#{ $paraglines } > -1){
        push(@{ $paragraphs },$paraglines);
        $paraglines = [];
      }
    }else{
      push(@{ $paraglines }, $line);
    }
  }
  if($#{ $paraglines } > -1){
    push(@{ $paragraphs },$paraglines);
  }
  $self->{'detail_paragraphs'} = $paragraphs;
  return $self;
}

sub detail_paragraphs{
  my $self = shift;
  $self->detail_breakdown unless(defined($self->{'detail_paragraphs'}));
  return $self->{'detail_paragraphs'};
}

sub detail_sentences{
  my $self = shift;
  return $self->{'detail_sentences'} if(defined($self->{'detail_sentences'}));
  $self->detail_breakdown unless(defined($self->{'detail_paragraphs'}));
  foreach my $paragraph (@{ $self->{'detail_paragraphs'} }){
    my $pgraphoneline = join(' ',@{$paragraph});
    my @sentences = split(/\. /,$pgraphoneline);
    push(@{ $self->{'detail_sentences'} }, @sentences);
  }
  return $self->{'detail_sentences'};
}

sub severity{
  my $self = shift;
  return $self->{'severity'};
}

sub attacker_capability{
  my $self = shift;
  $self->{'sev_level'} = {
                           'tricked_open_crafted' =>  0x1,
                         };
  return $self->{'attacker_capability'} if(defined($self->{'attacker_capability'}));
  $self->detail_sentences unless(defined($self->{'detail_sentences'}));
  foreach my $sentence (@{ $self->{'detail_sentences'} }){
    my ($who, $condition, $what);
    my ($got_who, $got_condition, $got_what) = (0,0,0);
    if($sentence =~m/attacker/){
        push(@{ $self->{'attacker_capability'} }, "$sentence.");
        # $self->{'severity'}=$self->{'severity'}|$self->{'sev_level'}->{'tricked_open_crafted'} if($sentence =~m/tricked\s+into\s+opening\s+a\s+(specially)*\s+crafted/);

#        $handled=1 if($sentence=~m/remote\s+attacker.*denial\s+of\s+service/);

#        $handled=1 if($sentence=~m/attacker.*denial\s+of\s+service/);
#        $handled=1 if($sentence=~m/attacker\s+could.*arbitrary\s+code\s+as\s+the\s+user/);
#        $handled=1 if($sentence=~m/attacker\s+could.*obtain\s+authentication\s+tokens/);

#        $handled=1 if($sentence=~m/tricked\s+in\s*to\s+(using|opening|viewing)\s+a\s+(specially\s+)*crafted/);
#        $handled=1 if($sentence=~m/tricked\s+into\s+viewing\s+a\s+malicious\s+site/);
#        $handled=1 if($sentence=~m/tricked\s+into\s+connecting\s+to\s+a\s+malicious.*server/);

        if($sentence =~m/((([Aa](n)*|[Tt]he)\s+)*(((phy(sica|scia)lly\s+)*(user-assisted\s+|proximate\s+|unprivileged\s+|privileged\s+)*)*([Rr]emo(t|v)e(,)*\s+|[Ll]ocal\s+)*(authorized\s+|authenticated\s+|unauthenticated\s+)*|(unathenticated\s+|authenticated\s+)*(remote\s+|local\s+))*(NFS\s+server\s+)*(\()*attacker(\))*(s)*)/){ $who=$1; $got_who=1; }

        my $mangled_sentence=$sentence;
        my $sed_who=$who; $sed_who=~s/\(/\\\(/g; $sed_who=~s/\)/\\\)/g;
        $mangled_sentence=~s/$sed_who/~attacker~/;
        if($mangled_sentence =~m/^\s*~attacker~\s*$/){
          $mangled_sentence=$sentence;
          $mangled_sentence=~s/$sed_who.*/~attacker~/;
        }

        if($mangled_sentence=~m/((could(,)*\s+|may\s+|might\s+|can\s+|access\s+to\s+restricted\s+|to\s+(break|bypass|cause|conduct|confuse|contact|corrupt|create|determine|discover|execute|expose|gain|inject|load|obtain|open|perform|possibly\s+(execute|obtain)|recover|spoof|view)\s+|'s\s+dialog\s+to\s+be\s+displayed\s+over\s+another\s+sites\s+content|would\s+be\s+isolated|would\s+need\s+write\s+access|more\s+information|cannot\s+exploit\s+this).*)/){ $what=$1; $got_what=1; }
        my $sed_what=$what; $sed_what=~s/\(/\\\(/g; $sed_what=~s/\)/\\\)/g;
        $mangled_sentence=~s/$sed_what/~capability~/;
        print STDERR "$mangled_sentence\n" unless($got_who&$got_what);
        $mangled_sentence=~s/~attacker~//;
        $mangled_sentence=~s/~capability~//;
        $condition=$mangled_sentence; $got_condition=1;

    }
  }
  return $self->{'attacker_capability'};
}
1;

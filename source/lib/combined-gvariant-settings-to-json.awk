# UBS VPN Controller v2.4.0 - bounded, read-only GVariant GetSettings decoder.
# AWK is a standard POSIX tool; no code execution or shell evaluation of input.
# Only a typed, non-secret a{sa{sv}} subset is accepted. Unknown signatures fail closed.
# Diagnostics reveal only static grammar categories, never actual network values.
function fail(reason) {
  if (ubs24_variant_diag == 1 && !reported++) {
    if (reason == "") reason="unsupported token or structure"
    print "DIAG: decoder category: " reason > "/dev/stderr"
  }
  invalid=1; exit 1
}
function space() { while (pos<=n && substr(src,pos,1) ~ /[ \t\r\n]/) pos++ }
function peek(    v) { space(); return substr(src,pos,1) }
function take(x) { if(peek()!=x) fail("unexpected delimiter or dictionary shape"); pos++ }
function word(w,    chunk,nextc) {
  space(); chunk=substr(src,pos,length(w)); if(chunk!=w) fail("unsupported typed scalar annotation")
  nextc=substr(src,pos+length(w),1)
  if(nextc ~ /[A-Za-z0-9_-]/) fail()
  pos+=length(w)
}
function quoted(    c,s) {
  take("'"); s=""
  while(pos<=n) {
    c=substr(src,pos++,1)
    if(c=="'") return s
    # Reject GVariant escapes and control characters rather than interpreting them.
    if(c=="\\" || c=="\"" || c ~ /[[:cntrl:]]/ || c !~ /^[ -~]$/) fail("quoted value requires unsupported escaping or character set")
    s=s c
    if(length(s)>8192) fail()
  }
  fail()
}
function jsonq(s){ return "\"" s "\"" }
function number(kind,    s,c,limit) {
  space(); s=""; c=substr(src,pos,1)
  if(c=="-"){ if(kind!="i")fail(); s="-"; pos++ }
  while(pos<=n && substr(src,pos,1) ~ /[0-9]/) {
    s=s substr(src,pos++,1)
    if(length(s)>11) fail()
  }
  if(s=="" || s=="-" || s ~ /^-?0[0-9]/) fail()
  if(substr(src,pos,1) ~ /[A-Za-z0-9_.]/) fail()
  if(kind=="u" && (s+0)>4294967295) fail()
  if(kind=="i" && ((s+0)<-2147483648 || (s+0)>2147483647)) fail()
  return s
}
# A uint64 version must fit the existing JSON verifier's exact-integer range.
# Validate decimal bounds lexicographically: awk floating-point arithmetic
# would lose precision for large t values. Never accept untyped numbers.
function number64(    s,c,limit,j,a,b) {
  space(); s=""
  while(pos<=n && substr(src,pos,1) ~ /[0-9]/) {
    s=s substr(src,pos++,1)
    if(length(s)>16) fail()
  }
  if(s=="" || (length(s)>1 && substr(s,1,1)=="0")) fail()
  if(substr(src,pos,1) ~ /[A-Za-z0-9_.-]/) fail()
  limit="9007199254740991"
  if(length(s)>length(limit)) fail()
  if(length(s)==length(limit)) {
    for(j=1;j<=length(limit);j++) {
      a=substr(s,j,1)+0; b=substr(limit,j,1)+0
      if(a>b) fail()
      if(a<b) break
    }
  }
  return s
}
# All dictionaries have distinct keys. Explicitly reject duplicate JSON keys.
function dictionary(which,    key,value,result,sep,id) {
  take("{"); result="{"; sep=""; id=++serial
  if(peek()=="}"){ pos++; return result "}" }
  while(1) {
    key=quoted(); if(key=="" || length(key)>256 || seen[id SUBSEP key]++) fail()
    take(":")
    if(which=="settings") value=dictionary("variants")
    else if(which=="variants") value=variant()
    else if(which=="strings") value=jsonq(quoted())
    else fail()
    result=result sep jsonq(key) ":" value
    if(length(result)>262144) fail()
    if(peek()=="}"){pos++;break}
    take(",");sep=","; if(peek()=="}")fail()
  }
  return result "}"
}
# Decode only explicitly typed byte arrays. GVariant often annotates just the
# first byte, printing later elements as bare 0xNN; the first annotation is
# mandatory even with @ay, to distinguish bytes from untyped numeric arrays.
# Emit integer octets in the historical typed-JSON {type:"ay",data:[...]} shape.
function byte_value(first,    s,h,j,digit,value) {
  space()
  if(substr(src,pos,4)=="byte") {word("byte");space()}
  else if(first) fail("byte array missing typed first element")
  if(substr(src,pos,2)!="0x") fail("invalid byte literal")
  pos+=2; s=substr(src,pos,2)
  if(length(s)!=2 || s !~ /^[0-9a-fA-F][0-9a-fA-F]$/) fail("invalid byte literal")
  pos+=2
  if(substr(src,pos,1) ~ /[A-Za-z0-9_.-]/) fail("invalid byte literal")
  value=0
  for(j=1;j<=2;j++) {
    digit=index("0123456789abcdef",tolower(substr(s,j,1)))-1
    value=16*value+digit
  }
  return value
}
# GVariant may print a nul-terminated ay as a bytestring, rather than an array.
# Support its strict ASCII/three-octal-digit subset; no shell interpretation,
# unknown escapes, literal control characters or non-ASCII text. A bytestring
# always appends precisely one nul octet; embedded nul is not accepted here.
function byte_string(    quote,c,nextc,oct,j,value,result,sep,count,code) {
  word("b"); quote=substr(src,pos,1)
  if(quote!="'" && quote!="\"") fail("invalid bytestring delimiter")
  pos++;result="[";sep="";count=0
  while(pos<=n) {
    c=substr(src,pos++,1)
    if(c==quote) {
      result=result sep "0]"
      if(length(result)>262144) fail()
      return result
    }
    if(c=="\\") {
      nextc=substr(src,pos++,1)
      if(nextc=="" || pos>n+1) fail("invalid bytestring escape")
      if(nextc ~ /^[0-7]$/) {
        oct=nextc substr(src,pos,2)
        if(length(oct)!=3 || oct !~ /^[0-7][0-7][0-7]$/) fail("invalid bytestring escape")
        pos+=2; value=0
        for(j=1;j<=3;j++) value=value*8+(substr(oct,j,1)+0)
        if(value>255) fail("invalid bytestring escape")
      } else if(nextc=="a")value=7
      else if(nextc=="b")value=8
      else if(nextc=="f")value=12
      else if(nextc=="n")value=10
      else if(nextc=="r")value=13
      else if(nextc=="t")value=9
      else if(nextc=="v")value=11
      else if(nextc=="\\")value=92
      else if(nextc=="'")value=39
      else if(nextc=="\"")value=34
      else fail("invalid bytestring escape")
    } else {
      if(c ~ /[[:cntrl:]]/ || c !~ /^[ -~]$/) fail("unsupported bytestring character")
      value=-1
      for(j=32;j<=126;j++) if(sprintf("%c",j)==c){ value=j;break }
      if(value<0) fail("unsupported bytestring character")
    }
    if(value==0) fail("embedded nul in bytestring")
    result=result sep value;sep=",";count++
    if(count>8192 || length(result)>262144) fail()
  }
  fail("unterminated bytestring")
}
# Only the fully annotated a(ayuay) container may supply tuple identity.
# Its (ay,u,ay) elements are legacy NetworkManager IPv6 address records.
# Keep the exact typed JSON shape as arrays [octets, uint32, octets].
# Neither the address bytes nor the prefix are trusted as network policy;
# that remains the responsibility of the existing settings verifier.
function tuple_byte_array(    value) {
  space()
  if(substr(src,pos,3)=="@ay" && substr(src,pos+3,1) ~ /[ \t\r\n]/) {
    pos+=3;space()
  }
  if(peek()=="[") return array_val("ay")
  if(substr(src,pos,1)=="b" && (substr(src,pos+1,1)=="'" || substr(src,pos+1,1)=="\""))
    return byte_string()
  fail("invalid tuple byte-array element")
}
function tuple_ipv6_address(    addr,prefix,gateway) {
  take("(")
  addr=tuple_byte_array()
  take(",")
  space()
  # The outer @a(ayuay) supplies the uint32 type. GVariant may abbreviate
  # its scalar annotation, so accept both uint32 64 and bare 64, with the
  # same unsigned 32-bit value validation.
  if(substr(src,pos,6)=="uint32") word("uint32")
  prefix=number("u")
  take(",")
  gateway=tuple_byte_array()
  take(")")
  return "[" addr "," prefix "," gateway "]"
}
function array_val(expected,    result,sep,one,kind,first) {
  take("["); result="["; sep="";first=1
  if(peek()=="]") {
    pos++
    if(expected=="") fail()
    if(expected!="as" && expected!="au" && expected!="ay" && expected!="aa{sv}" && expected!="aau" && expected!="aay" && expected!="a(ayuayu)" && expected!="a(ayuay)") fail()
    type=expected; return result "]"
  }
  if(peek()=="(") {
    if(expected!="a(ayuay)") fail("untyped tuple array")
    kind="a(ayuay)"
  }
  else if(peek()=="{") kind="aa{sv}"
  else if(peek()=="'")kind="as"
  else if(substr(src,pos,6)=="uint32") kind="au"
  else if(substr(src,pos,4)=="byte") kind="ay"
  else if(substr(src,pos,6)=="uint16") fail("unsupported uint16-array element type")
  else fail("unsupported array element type")
  if(expected!="" && expected!=kind) fail("array type differs from declared annotation")
  type=kind
  while(1) {
    if(kind=="a(ayuay)") one=tuple_ipv6_address()
    else if(kind=="aa{sv}")one=dictionary("variants")
    else if(kind=="as") one=jsonq(quoted())
    else if(kind=="ay") one=byte_value(first)
    else { word("uint32"); one=number("u") }
    result=result sep one
    if(length(result)>262144) fail()
    if(peek()=="]"){pos++;break}
    take(",");sep=",";first=0;if(peek()=="]") fail()
  }
  type=kind; return result "]"
}
# Diagnostics may reveal only an entire, syntactically valid GVariant type
# signature. A hardcoded handful of array shapes concealed real-world nested
# signatures and made the Arch probe repeatedly report only a generic failure.
# Validate structure recursively, without reading any payload values, before
# printing the signature. This is diagnostic-only: it does NOT permit any new
# types in the trusted settings decoder.
function signature_basic(c) { return index("ybnqiuxthdsogv",c)>0 }
function signature_type(depth,may_dict,    c,key,fields) {
  if(depth>16 || sigpos>length(sigtext)) return 0
  c=substr(sigtext,sigpos++,1)
  if(c=="a") return signature_type(depth+1,1)
  if(c=="m") return signature_type(depth+1,0)
  if(c=="(") {
    fields=0
    while(sigpos<=length(sigtext) && substr(sigtext,sigpos,1)!=")") {
      if(!signature_type(depth+1,0)) return 0
      if(++fields>32) return 0
    }
    if(fields==0 || sigpos>length(sigtext)) return 0
    sigpos++; return 1
  }
  if(c=="{") {
    if(!may_dict || sigpos>length(sigtext)) return 0
    key=substr(sigtext,sigpos++,1)
    if(!signature_basic(key) || key=="v") return 0
    if(!signature_type(depth+1,0)) return 0
    if(substr(sigtext,sigpos++,1)!="}") return 0
    return 1
  }
  return signature_basic(c)
}
function printable_signature(sig) {
  if(length(sig)<1 || length(sig)>64) return 0
  # No quotes, whitespace, arbitrary identifiers or settings values can pass.
  if(sig !~ /^[ybnqiuxthdsogvam(){}]+$/) return 0
  sigtext=sig; sigpos=1
  return signature_type(0,0) && sigpos==length(sigtext)+1
}
function variant(    hint,kind,v,c,ann) {
  take("<"); hint="";space()
  if(peek()=="@"){
    pos++;ann=""
    while(pos<=n && substr(src,pos,1) !~ /[ \t\r\n]/) { ann=ann substr(src,pos++,1);if(length(ann)>32)fail() }
    if(ann!="as"&&ann!="au"&&ann!="ay"&&ann!="aa{sv}"&&ann!="aau"&&ann!="aay"&&ann!="a(ayuayu)"&&ann!="a(ayuay)"&&ann!="a{ss}"&&ann!="a{sv}") {
      if(ubs24_variant_diag == 1 && printable_signature(ann))
        print "DIAG: unsupported GVariant type signature: @" ann > "/dev/stderr"
      fail("unsupported explicit type annotation")
    }
    hint=ann
  }
  c=peek()
  if(c=="'") { kind="s";v=jsonq(quoted()) }
  else if(c=="{") {
    if(hint=="a{sv}") {kind="a{sv}";v=dictionary("variants")}
    else {kind="a{ss}";v=dictionary("strings")}
  }
  else if(c=="[") {v=array_val(hint);kind=type}
  else if(c=="b" && (substr(src,pos+1,1)=="'" || substr(src,pos+1,1)=="\"")) {kind="ay";v=byte_string()}
  else if(substr(src,pos,6)=="uint32") {word("uint32");kind="u";v=number("u")}
  # GetSettings variants may contain timestamps or other uint64 properties.
  # Preserve the D-Bus 't' type; only emit exact JSON integers within the
  # already-established number64 safe bound. Never round larger uint64s.
  else if(substr(src,pos,6)=="uint64") {word("uint64");kind="t";v=number64()}
  else if(substr(src,pos,5)=="int32") {word("int32");kind="i";v=number("i")}
  else if(substr(src,pos,4)=="true") {word("true");kind="b";v="true"}
  else if(substr(src,pos,5)=="false") {word("false");kind="b";v="false"}
  else if(c=="-" || c ~ /[0-9]/){kind="i";v=number("i")}
  else if(substr(src,pos,5)=="int64") fail("unsupported int64 scalar type")
  else if(substr(src,pos,4)=="byte") fail("unsupported byte scalar type")
  else if(substr(src,pos,10)=="objectpath") fail("unsupported object-path scalar type")
  else fail("unsupported GVariant scalar/container type")
  if(hint!="" && kind!=hint) fail()
  take(">")
  return "{\"type\":" jsonq(kind) ",\"data\":" v "}"
}
{
  if(NR>1) src=src "\n" $0; else src=$0
  if(length(src)>262144) fail()
}
END {
  if(invalid || NR==0) exit 1
  n=length(src);pos=1; serial=0
  # Explicitly selected shape. GetSettings and GetAppliedConnection have
  # different D-Bus result signatures; never infer/ignore the version field.
  if (ubs24_variant_mode != "" && ubs24_variant_mode != "settings" && ubs24_variant_mode != "applied") exit 1
  take("("); result=dictionary("settings");take(",")
  if (ubs24_variant_mode == "applied") {
    word("uint64"); ver=number64()
    take(")")
    if(peek()!="") exit 1
    print "{\"type\":\"a{sa{sv}}t\",\"data\":[" result "," ver "]}"
  } else {
    take(")")
    if(peek()!="") exit 1
    print "{\"type\":\"a{sa{sv}}\",\"data\":[" result "]}"
  }
}

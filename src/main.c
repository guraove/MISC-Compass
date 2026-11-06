#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* Signatures are hints, not proof that a file is valid. */
typedef struct { const unsigned char *bytes; size_t length; const char *name; const char *next; } Signature;
static const unsigned char png[]={0x89,'P','N','G',13,10,26,10}, jpg[]={0xff,0xd8,0xff}, zip[]={'P','K',3,4}, zip_empty[]={'P','K',5,6}, zip_span[]={'P','K',7,8}, pdf[]={'%','P','D','F','-'}, gif87[]={'G','I','F','8','7','a'}, gif89[]={'G','I','F','8','9','a'}, gz[]={0x1f,0x8b}, rar4[]={'R','a','r','!',0x1a,7,0}, rar5[]={'R','a','r','!',0x1a,7,1,0}, elf[]={0x7f,'E','L','F'}, pe[]={'M','Z'}, wav[]={'R','I','F','F'};
static const Signature sigs[]={
 {png,sizeof png,"PNG image","Inspect metadata and image dimensions; check for extra data after IEND."},
 {jpg,sizeof jpg,"JPEG image","Inspect EXIF metadata and check for data after the end marker."},
 {zip,sizeof zip,"ZIP archive","List archive entries before extracting; Office documents may also use ZIP."},
 {zip_empty,sizeof zip_empty,"ZIP archive (empty signature)","List archive entries before extracting."},
 {zip_span,sizeof zip_span,"ZIP archive (spanned signature)","Inspect the archive structure before extracting."},
 {pdf,sizeof pdf,"PDF document","Inspect document metadata and embedded objects."},
 {gif87,sizeof gif87,"GIF image","Inspect frames, metadata and data after the trailer."},
 {gif89,sizeof gif89,"GIF image","Inspect frames, metadata and data after the trailer."},
 {gz,sizeof gz,"gzip stream","Inspect or decompress a copy with a trusted tool."},
 {rar5,sizeof rar5,"RAR archive","List entries before extracting."},
 {rar4,sizeof rar4,"RAR archive","List entries before extracting."},
 {elf,sizeof elf,"ELF executable","Inspect headers and strings without executing it."},
 {pe,sizeof pe,"Possible DOS/PE executable","Inspect headers without executing the file; MZ alone does not confirm PE."},
 {wav,sizeof wav,"RIFF container","Inspect the container subtype at offset 8 (e.g. WAVE or WEBP)."}
};
static void usage(const char *exe) { printf("MISC-Compass 0.2.1\nUsage: %s <file>\n       %s --help\n",exe,exe); }
int main(int argc,char **argv) {
 FILE *f; unsigned char buf[8192], head[16]; size_t n,i,hn=0; unsigned long long count=0, freq[256]={0}, printable=0, run=0; double entropy=0; const Signature *match=NULL; char sample[81]; size_t sl=0; int shown=0; unsigned char window[8]={0}; size_t wn=0; int embedded=0; const Signature *found[10]; unsigned long long offsets[10];
 if(argc==2 && (!strcmp(argv[1],"--help") || !strcmp(argv[1],"-h"))) {usage(argv[0]); return 0;}
 if(argc!=2) {usage(argv[0]); return 2;}
 f=fopen(argv[1],"rb"); if(!f) {perror("Cannot open file"); return 1;}
 puts("MISC-Compass 0.2.1 | offline, read-only analysis");
 puts("Printable ASCII strings (first 10, minimum 4 characters; truncated at 80):");
 while((n=fread(buf,1,sizeof buf,f))>0) for(i=0;i<n;i++) {
  unsigned char c=buf[i];
  /* Keep a rolling window so signatures crossing read boundaries are found. */
  if(wn<sizeof window) window[wn++]=c;
  else {memmove(window,window+1,sizeof window-1); window[sizeof window-1]=c;}
  if(embedded<10) {
   size_t j;
   for(j=0;j<sizeof sigs/sizeof sigs[0];j++) {
    size_t len=sigs[j].length;
    if(wn>=len && count+1>len && !memcmp(window+wn-len,sigs[j].bytes,len)) {
     found[embedded]=&sigs[j]; offsets[embedded]=count+1-(unsigned long long)len;
     embedded++; break;
    }
   }
  }
  if(hn<sizeof head) head[hn++]=c; freq[c]++; count++;
  if(c>=32 && c<=126) {printable++; run++; if(sl<80) sample[sl++]=(char)c;}
  else {if(run>=4 && shown<10) {sample[sl]='\0'; printf("  %s%s\n",sample,run>80?"...":""); shown++;} run=0; sl=0;}
 }
 if(ferror(f)) {fputs("Error reading file.\n",stderr); fclose(f); return 1;}
 if(run>=4 && shown<10) {sample[sl]='\0'; printf("  %s%s\n",sample,run>80?"...":""); shown++;}
 if(!shown) puts("  (none)");
 puts("\nEmbedded signatures (first 10):");
 if(!embedded) puts("  (none)");
 for(i=0;i<(size_t)embedded;i++) printf("  Embedded signature at offset %llu (0x%llX): %s\n",offsets[i],offsets[i],found[i]->name);
 fclose(f);
 for(i=0;i<sizeof sigs/sizeof sigs[0];i++) if(hn>=sigs[i].length && !memcmp(head,sigs[i].bytes,sigs[i].length)) {match=&sigs[i]; break;}
 for(i=0;i<256;i++) if(freq[i] && count) {double p=(double)freq[i]/(double)count; entropy-=p*log(p)/log(2.0);}
 printf("\nSize: %llu bytes\nHeader:",count); for(i=0;i<hn;i++) printf(" %02X",head[i]); if(!hn) printf(" (empty)");
 printf("\nPossible type: %s\n",match?match->name:"unknown");
 printf("ASCII printable bytes: %.1f%%\nEntropy: %.3f bits/byte\n",count?100.0*(double)printable/(double)count:0.0,entropy);
 puts("Embedded signatures are byte-pattern clues only; matches may be coincidental and are capped at 10.");
 puts("\nWhy: file signatures compare bytes at offset 0; extensions can be misleading. A match does not validate the file.");
 puts("Entropy measures byte diversity, not encryption: compressed and random-looking data can also score high. Small files can be misleading.");
 printf("Next: %s\n",match?match->next:"Check the hex header, filename and strings; an unknown signature does not imply malicious content.");
 puts("Treat extracted strings as untrusted clues. Avoid running unknown files."); return 0;
}

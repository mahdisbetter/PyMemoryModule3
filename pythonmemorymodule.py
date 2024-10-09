import ctypes
import ctypes.wintypes as wintypes
import threading
import collections
import os
import struct
import codecs
import time
import math
import string
import mmap

from collections import Counter
from hashlib import sha1
from hashlib import sha256
from hashlib import sha512
from hashlib import md5

import functools
import copy as copymod


"""

######################################################################################           ######################################################################################
###################################################################################### PEFILE.PY ######################################################################################
######################################################################################           ######################################################################################

"""

codecs.register_error('backslashreplace_',codecs.lookup_error('backslashreplace'))
long=int
def lru_cache(maxsize=128,typed=False,copy=False):
	if not copy:return functools.lru_cache(maxsize,typed)
	def decorator(f):
		cached_func=functools.lru_cache(maxsize,typed)(f)
		@functools.wraps(f)
		def wrapper(*args,**kwargs):return copymod.copy(cached_func(*args,**kwargs))
		return wrapper
	return decorator
@lru_cache(maxsize=2048)
def cache_adjust_SectionAlignment(val,section_alignment,file_alignment):
	if section_alignment<4096:section_alignment=file_alignment
	if section_alignment and val%section_alignment:return section_alignment*int(val/section_alignment)
	return val
def count_zeroes(data):return data.count(0)
fast_load=False
MAX_STRING_LENGTH=1048576
MAX_IMPORT_SYMBOLS=8192
MAX_IMPORT_NAME_LENGTH=512
MAX_DLL_LENGTH=512
MAX_SYMBOL_NAME_LENGTH=512
MAX_SECTIONS=2048
MAX_RESOURCE_ENTRIES=32768
MAX_RESOURCE_DEPTH=32
MAX_SYMBOL_EXPORT_COUNT=8192
IMAGE_DOS_SIGNATURE=23117
IMAGE_DOSZM_SIGNATURE=19802
IMAGE_NE_SIGNATURE=17742
IMAGE_LE_SIGNATURE=17740
IMAGE_LX_SIGNATURE=22604
IMAGE_TE_SIGNATURE=23126
IMAGE_NT_SIGNATURE=17744
IMAGE_NUMBEROF_DIRECTORY_ENTRIES=16
IMAGE_ORDINAL_FLAG=2147483648
IMAGE_ORDINAL_FLAG64=0x8000000000000000
OPTIONAL_HEADER_MAGIC_PE=267
OPTIONAL_HEADER_MAGIC_PE_PLUS=523
def two_way_dict(pairs):return dict([(e[1],e[0])for e in pairs]+pairs)
directory_entry_types=[('IMAGE_DIRECTORY_ENTRY_EXPORT',0),('IMAGE_DIRECTORY_ENTRY_IMPORT',1),('IMAGE_DIRECTORY_ENTRY_RESOURCE',2),('IMAGE_DIRECTORY_ENTRY_EXCEPTION',3),('IMAGE_DIRECTORY_ENTRY_SECURITY',4),('IMAGE_DIRECTORY_ENTRY_BASERELOC',5),('IMAGE_DIRECTORY_ENTRY_DEBUG',6),('IMAGE_DIRECTORY_ENTRY_COPYRIGHT',7),('IMAGE_DIRECTORY_ENTRY_GLOBALPTR',8),('IMAGE_DIRECTORY_ENTRY_TLS',9),('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG',10),('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT',11),('IMAGE_DIRECTORY_ENTRY_IAT',12),('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT',13),('IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR',14),('IMAGE_DIRECTORY_ENTRY_RESERVED',15)]
DIRECTORY_ENTRY=two_way_dict(directory_entry_types)
image_characteristics=[('IMAGE_FILE_RELOCS_STRIPPED',1),('IMAGE_FILE_EXECUTABLE_IMAGE',2),('IMAGE_FILE_LINE_NUMS_STRIPPED',4),('IMAGE_FILE_LOCAL_SYMS_STRIPPED',8),('IMAGE_FILE_AGGRESIVE_WS_TRIM',16),('IMAGE_FILE_LARGE_ADDRESS_AWARE',32),('IMAGE_FILE_16BIT_MACHINE',64),('IMAGE_FILE_BYTES_REVERSED_LO',128),('IMAGE_FILE_32BIT_MACHINE',256),('IMAGE_FILE_DEBUG_STRIPPED',512),('IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP',1024),('IMAGE_FILE_NET_RUN_FROM_SWAP',2048),('IMAGE_FILE_SYSTEM',4096),('IMAGE_FILE_DLL',8192),('IMAGE_FILE_UP_SYSTEM_ONLY',16384),('IMAGE_FILE_BYTES_REVERSED_HI',32768)]
IMAGE_CHARACTERISTICS=two_way_dict(image_characteristics)
section_characteristics=[('IMAGE_SCN_TYPE_REG',0),('IMAGE_SCN_TYPE_DSECT',1),('IMAGE_SCN_TYPE_NOLOAD',2),('IMAGE_SCN_TYPE_GROUP',4),('IMAGE_SCN_TYPE_NO_PAD',8),('IMAGE_SCN_TYPE_COPY',16),('IMAGE_SCN_CNT_CODE',32),('IMAGE_SCN_CNT_INITIALIZED_DATA',64),('IMAGE_SCN_CNT_UNINITIALIZED_DATA',128),('IMAGE_SCN_LNK_OTHER',256),('IMAGE_SCN_LNK_INFO',512),('IMAGE_SCN_LNK_OVER',1024),('IMAGE_SCN_LNK_REMOVE',2048),('IMAGE_SCN_LNK_COMDAT',4096),('IMAGE_SCN_MEM_PROTECTED',16384),('IMAGE_SCN_NO_DEFER_SPEC_EXC',16384),('IMAGE_SCN_GPREL',32768),('IMAGE_SCN_MEM_FARDATA',32768),('IMAGE_SCN_MEM_SYSHEAP',65536),('IMAGE_SCN_MEM_PURGEABLE',131072),('IMAGE_SCN_MEM_16BIT',131072),('IMAGE_SCN_MEM_LOCKED',262144),('IMAGE_SCN_MEM_PRELOAD',524288),('IMAGE_SCN_ALIGN_1BYTES',1048576),('IMAGE_SCN_ALIGN_2BYTES',2097152),('IMAGE_SCN_ALIGN_4BYTES',3145728),('IMAGE_SCN_ALIGN_8BYTES',4194304),('IMAGE_SCN_ALIGN_16BYTES',5242880),('IMAGE_SCN_ALIGN_32BYTES',6291456),('IMAGE_SCN_ALIGN_64BYTES',7340032),('IMAGE_SCN_ALIGN_128BYTES',8388608),('IMAGE_SCN_ALIGN_256BYTES',9437184),('IMAGE_SCN_ALIGN_512BYTES',10485760),('IMAGE_SCN_ALIGN_1024BYTES',11534336),('IMAGE_SCN_ALIGN_2048BYTES',12582912),('IMAGE_SCN_ALIGN_4096BYTES',13631488),('IMAGE_SCN_ALIGN_8192BYTES',14680064),('IMAGE_SCN_ALIGN_MASK',15728640),('IMAGE_SCN_LNK_NRELOC_OVFL',16777216),('IMAGE_SCN_MEM_DISCARDABLE',33554432),('IMAGE_SCN_MEM_NOT_CACHED',67108864),('IMAGE_SCN_MEM_NOT_PAGED',134217728),('IMAGE_SCN_MEM_SHARED',268435456),('IMAGE_SCN_MEM_EXECUTE',536870912),('IMAGE_SCN_MEM_READ',1073741824),('IMAGE_SCN_MEM_WRITE',2147483648)]
SECTION_CHARACTERISTICS=two_way_dict(section_characteristics)
debug_types=[('IMAGE_DEBUG_TYPE_UNKNOWN',0),('IMAGE_DEBUG_TYPE_COFF',1),('IMAGE_DEBUG_TYPE_CODEVIEW',2),('IMAGE_DEBUG_TYPE_FPO',3),('IMAGE_DEBUG_TYPE_MISC',4),('IMAGE_DEBUG_TYPE_EXCEPTION',5),('IMAGE_DEBUG_TYPE_FIXUP',6),('IMAGE_DEBUG_TYPE_OMAP_TO_SRC',7),('IMAGE_DEBUG_TYPE_OMAP_FROM_SRC',8),('IMAGE_DEBUG_TYPE_BORLAND',9),('IMAGE_DEBUG_TYPE_RESERVED10',10),('IMAGE_DEBUG_TYPE_CLSID',11),('IMAGE_DEBUG_TYPE_VC_FEATURE',12),('IMAGE_DEBUG_TYPE_POGO',13),('IMAGE_DEBUG_TYPE_ILTCG',14),('IMAGE_DEBUG_TYPE_MPX',15),('IMAGE_DEBUG_TYPE_REPRO',16),('IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS',20)]
DEBUG_TYPE=two_way_dict(debug_types)
subsystem_types=[('IMAGE_SUBSYSTEM_UNKNOWN',0),('IMAGE_SUBSYSTEM_NATIVE',1),('IMAGE_SUBSYSTEM_WINDOWS_GUI',2),('IMAGE_SUBSYSTEM_WINDOWS_CUI',3),('IMAGE_SUBSYSTEM_OS2_CUI',5),('IMAGE_SUBSYSTEM_POSIX_CUI',7),('IMAGE_SUBSYSTEM_NATIVE_WINDOWS',8),('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI',9),('IMAGE_SUBSYSTEM_EFI_APPLICATION',10),('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER',11),('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER',12),('IMAGE_SUBSYSTEM_EFI_ROM',13),('IMAGE_SUBSYSTEM_XBOX',14),('IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION',16)]
SUBSYSTEM_TYPE=two_way_dict(subsystem_types)
machine_types=[('IMAGE_FILE_MACHINE_UNKNOWN',0),('IMAGE_FILE_MACHINE_I386',332),('IMAGE_FILE_MACHINE_R3000',354),('IMAGE_FILE_MACHINE_R4000',358),('IMAGE_FILE_MACHINE_R10000',360),('IMAGE_FILE_MACHINE_WCEMIPSV2',361),('IMAGE_FILE_MACHINE_ALPHA',388),('IMAGE_FILE_MACHINE_SH3',418),('IMAGE_FILE_MACHINE_SH3DSP',419),('IMAGE_FILE_MACHINE_SH3E',420),('IMAGE_FILE_MACHINE_SH4',422),('IMAGE_FILE_MACHINE_SH5',424),('IMAGE_FILE_MACHINE_ARM',448),('IMAGE_FILE_MACHINE_THUMB',450),('IMAGE_FILE_MACHINE_ARMNT',452),('IMAGE_FILE_MACHINE_AM33',467),('IMAGE_FILE_MACHINE_POWERPC',496),('IMAGE_FILE_MACHINE_POWERPCFP',497),('IMAGE_FILE_MACHINE_IA64',512),('IMAGE_FILE_MACHINE_MIPS16',614),('IMAGE_FILE_MACHINE_ALPHA64',644),('IMAGE_FILE_MACHINE_AXP64',644),('IMAGE_FILE_MACHINE_MIPSFPU',870),('IMAGE_FILE_MACHINE_MIPSFPU16',1126),('IMAGE_FILE_MACHINE_TRICORE',1312),('IMAGE_FILE_MACHINE_CEF',3311),('IMAGE_FILE_MACHINE_EBC',3772),('IMAGE_FILE_MACHINE_RISCV32',20530),('IMAGE_FILE_MACHINE_RISCV64',20580),('IMAGE_FILE_MACHINE_RISCV128',20776),('IMAGE_FILE_MACHINE_LOONGARCH32',25138),('IMAGE_FILE_MACHINE_LOONGARCH64',25188),('IMAGE_FILE_MACHINE_AMD64',34404),('IMAGE_FILE_MACHINE_M32R',36929),('IMAGE_FILE_MACHINE_ARM64',43620),('IMAGE_FILE_MACHINE_CEE',49390)]
MACHINE_TYPE=two_way_dict(machine_types)
relocation_types=[('IMAGE_REL_BASED_ABSOLUTE',0),('IMAGE_REL_BASED_HIGH',1),('IMAGE_REL_BASED_LOW',2),('IMAGE_REL_BASED_HIGHLOW',3),('IMAGE_REL_BASED_HIGHADJ',4),('IMAGE_REL_BASED_MIPS_JMPADDR',5),('IMAGE_REL_BASED_SECTION',6),('IMAGE_REL_BASED_REL',7),('IMAGE_REL_BASED_MIPS_JMPADDR16',9),('IMAGE_REL_BASED_IA64_IMM64',9),('IMAGE_REL_BASED_DIR64',10),('IMAGE_REL_BASED_HIGH3ADJ',11)]
RELOCATION_TYPE=two_way_dict(relocation_types)
dll_characteristics=[('IMAGE_LIBRARY_PROCESS_INIT',1),('IMAGE_LIBRARY_PROCESS_TERM',2),('IMAGE_LIBRARY_THREAD_INIT',4),('IMAGE_LIBRARY_THREAD_TERM',8),('IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA',32),('IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE',64),('IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY',128),('IMAGE_DLLCHARACTERISTICS_NX_COMPAT',256),('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION',512),('IMAGE_DLLCHARACTERISTICS_NO_SEH',1024),('IMAGE_DLLCHARACTERISTICS_NO_BIND',2048),('IMAGE_DLLCHARACTERISTICS_APPCONTAINER',4096),('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER',8192),('IMAGE_DLLCHARACTERISTICS_GUARD_CF',16384),('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE',32768)]
DLL_CHARACTERISTICS=two_way_dict(dll_characteristics)
ex_dll_characteristics=[('IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT',1),('IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT_STRICT_MODE',2),('IMAGE_DLLCHARACTERISTICS_EX_CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE',4),('IMAGE_DLLCHARACTERISTICS_EX_CET_DYNAMIC_APIS_ALLOW_IN_PROC',8),('IMAGE_DLLCHARACTERISTICS_EX_CET_RESERVED_1',16),('IMAGE_DLLCHARACTERISTICS_EX_CET_RESERVED_2',32)]
EX_DLL_CHARACTERISTICS=two_way_dict(ex_dll_characteristics)
MIN_VALID_FILE_ALIGNMENT=512
SECTOR_SIZE=512
unwind_info_flags=[('UNW_FLAG_EHANDLER',1),('UNW_FLAG_UHANDLER',2),('UNW_FLAG_CHAININFO',4)]
UNWIND_INFO_FLAGS=two_way_dict(unwind_info_flags)
registers=[('RAX',0),('RCX',1),('RDX',2),('RBX',3),('RSP',4),('RBP',5),('RSI',6),('RDI',7),('R8',8),('R9',9),('R10',10),('R11',11),('R12',12),('R13',13),('R14',14),('R15',15)]
REGISTERS=two_way_dict(registers)
UWOP_PUSH_NONVOL=0
UWOP_ALLOC_LARGE=1
UWOP_ALLOC_SMALL=2
UWOP_SET_FPREG=3
UWOP_SAVE_NONVOL=4
UWOP_SAVE_NONVOL_FAR=5
UWOP_EPILOG=6
UWOP_SAVE_XMM128=8
UWOP_SAVE_XMM128_FAR=9
UWOP_PUSH_MACHFRAME=10
resource_type=[('RT_CURSOR',1),('RT_BITMAP',2),('RT_ICON',3),('RT_MENU',4),('RT_DIALOG',5),('RT_STRING',6),('RT_FONTDIR',7),('RT_FONT',8),('RT_ACCELERATOR',9),('RT_RCDATA',10),('RT_MESSAGETABLE',11),('RT_GROUP_CURSOR',12),('RT_GROUP_ICON',14),('RT_VERSION',16),('RT_DLGINCLUDE',17),('RT_PLUGPLAY',19),('RT_VXD',20),('RT_ANICURSOR',21),('RT_ANIICON',22),('RT_HTML',23),('RT_MANIFEST',24)]
RESOURCE_TYPE=two_way_dict(resource_type)
lang=[('LANG_NEUTRAL',0),('LANG_INVARIANT',127),('LANG_AFRIKAANS',54),('LANG_ALBANIAN',28),('LANG_ARABIC',1),('LANG_ARMENIAN',43),('LANG_ASSAMESE',77),('LANG_AZERI',44),('LANG_BASQUE',45),('LANG_BELARUSIAN',35),('LANG_BENGALI',69),('LANG_BULGARIAN',2),('LANG_CATALAN',3),('LANG_CHINESE',4),('LANG_CROATIAN',26),('LANG_CZECH',5),('LANG_DANISH',6),('LANG_DIVEHI',101),('LANG_DUTCH',19),('LANG_ENGLISH',9),('LANG_ESTONIAN',37),('LANG_FAEROESE',56),('LANG_FARSI',41),('LANG_FINNISH',11),('LANG_FRENCH',12),('LANG_GALICIAN',86),('LANG_GEORGIAN',55),('LANG_GERMAN',7),('LANG_GREEK',8),('LANG_GUJARATI',71),('LANG_HEBREW',13),('LANG_HINDI',57),('LANG_HUNGARIAN',14),('LANG_ICELANDIC',15),('LANG_INDONESIAN',33),('LANG_ITALIAN',16),('LANG_JAPANESE',17),('LANG_KANNADA',75),('LANG_KASHMIRI',96),('LANG_KAZAK',63),('LANG_KONKANI',87),('LANG_KOREAN',18),('LANG_KYRGYZ',64),('LANG_LATVIAN',38),('LANG_LITHUANIAN',39),('LANG_MACEDONIAN',47),('LANG_MALAY',62),('LANG_MALAYALAM',76),('LANG_MANIPURI',88),('LANG_MARATHI',78),('LANG_MONGOLIAN',80),('LANG_NEPALI',97),('LANG_NORWEGIAN',20),('LANG_ORIYA',72),('LANG_POLISH',21),('LANG_PORTUGUESE',22),('LANG_PUNJABI',70),('LANG_ROMANIAN',24),('LANG_RUSSIAN',25),('LANG_SANSKRIT',79),('LANG_SERBIAN',26),('LANG_SINDHI',89),('LANG_SLOVAK',27),('LANG_SLOVENIAN',36),('LANG_SPANISH',10),('LANG_SWAHILI',65),('LANG_SWEDISH',29),('LANG_SYRIAC',90),('LANG_TAMIL',73),('LANG_TATAR',68),('LANG_TELUGU',74),('LANG_THAI',30),('LANG_TURKISH',31),('LANG_UKRAINIAN',34),('LANG_URDU',32),('LANG_UZBEK',67),('LANG_VIETNAMESE',42),('LANG_GAELIC',60),('LANG_MALTESE',58),('LANG_MAORI',40),('LANG_RHAETO_ROMANCE',23),('LANG_SAAMI',59),('LANG_SORBIAN',46),('LANG_SUTU',48),('LANG_TSONGA',49),('LANG_TSWANA',50),('LANG_VENDA',51),('LANG_XHOSA',52),('LANG_ZULU',53),('LANG_ESPERANTO',143),('LANG_WALON',144),('LANG_CORNISH',145),('LANG_WELSH',146),('LANG_BRETON',147)]
LANG=two_way_dict(lang)
sublang=[('SUBLANG_NEUTRAL',0),('SUBLANG_DEFAULT',1),('SUBLANG_SYS_DEFAULT',2),('SUBLANG_ARABIC_SAUDI_ARABIA',1),('SUBLANG_ARABIC_IRAQ',2),('SUBLANG_ARABIC_EGYPT',3),('SUBLANG_ARABIC_LIBYA',4),('SUBLANG_ARABIC_ALGERIA',5),('SUBLANG_ARABIC_MOROCCO',6),('SUBLANG_ARABIC_TUNISIA',7),('SUBLANG_ARABIC_OMAN',8),('SUBLANG_ARABIC_YEMEN',9),('SUBLANG_ARABIC_SYRIA',10),('SUBLANG_ARABIC_JORDAN',11),('SUBLANG_ARABIC_LEBANON',12),('SUBLANG_ARABIC_KUWAIT',13),('SUBLANG_ARABIC_UAE',14),('SUBLANG_ARABIC_BAHRAIN',15),('SUBLANG_ARABIC_QATAR',16),('SUBLANG_AZERI_LATIN',1),('SUBLANG_AZERI_CYRILLIC',2),('SUBLANG_CHINESE_TRADITIONAL',1),('SUBLANG_CHINESE_SIMPLIFIED',2),('SUBLANG_CHINESE_HONGKONG',3),('SUBLANG_CHINESE_SINGAPORE',4),('SUBLANG_CHINESE_MACAU',5),('SUBLANG_DUTCH',1),('SUBLANG_DUTCH_BELGIAN',2),('SUBLANG_ENGLISH_US',1),('SUBLANG_ENGLISH_UK',2),('SUBLANG_ENGLISH_AUS',3),('SUBLANG_ENGLISH_CAN',4),('SUBLANG_ENGLISH_NZ',5),('SUBLANG_ENGLISH_EIRE',6),('SUBLANG_ENGLISH_SOUTH_AFRICA',7),('SUBLANG_ENGLISH_JAMAICA',8),('SUBLANG_ENGLISH_CARIBBEAN',9),('SUBLANG_ENGLISH_BELIZE',10),('SUBLANG_ENGLISH_TRINIDAD',11),('SUBLANG_ENGLISH_ZIMBABWE',12),('SUBLANG_ENGLISH_PHILIPPINES',13),('SUBLANG_FRENCH',1),('SUBLANG_FRENCH_BELGIAN',2),('SUBLANG_FRENCH_CANADIAN',3),('SUBLANG_FRENCH_SWISS',4),('SUBLANG_FRENCH_LUXEMBOURG',5),('SUBLANG_FRENCH_MONACO',6),('SUBLANG_GERMAN',1),('SUBLANG_GERMAN_SWISS',2),('SUBLANG_GERMAN_AUSTRIAN',3),('SUBLANG_GERMAN_LUXEMBOURG',4),('SUBLANG_GERMAN_LIECHTENSTEIN',5),('SUBLANG_ITALIAN',1),('SUBLANG_ITALIAN_SWISS',2),('SUBLANG_KASHMIRI_SASIA',2),('SUBLANG_KASHMIRI_INDIA',2),('SUBLANG_KOREAN',1),('SUBLANG_LITHUANIAN',1),('SUBLANG_MALAY_MALAYSIA',1),('SUBLANG_MALAY_BRUNEI_DARUSSALAM',2),('SUBLANG_NEPALI_INDIA',2),('SUBLANG_NORWEGIAN_BOKMAL',1),('SUBLANG_NORWEGIAN_NYNORSK',2),('SUBLANG_PORTUGUESE',2),('SUBLANG_PORTUGUESE_BRAZILIAN',1),('SUBLANG_SERBIAN_LATIN',2),('SUBLANG_SERBIAN_CYRILLIC',3),('SUBLANG_SPANISH',1),('SUBLANG_SPANISH_MEXICAN',2),('SUBLANG_SPANISH_MODERN',3),('SUBLANG_SPANISH_GUATEMALA',4),('SUBLANG_SPANISH_COSTA_RICA',5),('SUBLANG_SPANISH_PANAMA',6),('SUBLANG_SPANISH_DOMINICAN_REPUBLIC',7),('SUBLANG_SPANISH_VENEZUELA',8),('SUBLANG_SPANISH_COLOMBIA',9),('SUBLANG_SPANISH_PERU',10),('SUBLANG_SPANISH_ARGENTINA',11),('SUBLANG_SPANISH_ECUADOR',12),('SUBLANG_SPANISH_CHILE',13),('SUBLANG_SPANISH_URUGUAY',14),('SUBLANG_SPANISH_PARAGUAY',15),('SUBLANG_SPANISH_BOLIVIA',16),('SUBLANG_SPANISH_EL_SALVADOR',17),('SUBLANG_SPANISH_HONDURAS',18),('SUBLANG_SPANISH_NICARAGUA',19),('SUBLANG_SPANISH_PUERTO_RICO',20),('SUBLANG_SWEDISH',1),('SUBLANG_SWEDISH_FINLAND',2),('SUBLANG_URDU_PAKISTAN',1),('SUBLANG_URDU_INDIA',2),('SUBLANG_UZBEK_LATIN',1),('SUBLANG_UZBEK_CYRILLIC',2),('SUBLANG_DUTCH_SURINAM',3),('SUBLANG_ROMANIAN',1),('SUBLANG_ROMANIAN_MOLDAVIA',2),('SUBLANG_RUSSIAN',1),('SUBLANG_RUSSIAN_MOLDAVIA',2),('SUBLANG_CROATIAN',1),('SUBLANG_LITHUANIAN_CLASSIC',2),('SUBLANG_GAELIC',1),('SUBLANG_GAELIC_SCOTTISH',2),('SUBLANG_GAELIC_MANX',3)]
SUBLANG=two_way_dict(sublang)
SUBLANG=dict(sublang)
for(sublang_name,sublang_value)in sublang:
	if sublang_value in SUBLANG:SUBLANG[sublang_value].append(sublang_name)
	else:SUBLANG[sublang_value]=[sublang_name]
def get_sublang_name_for_lang(lang_value,sublang_value):
	lang_name=LANG.get(lang_value,'*unknown*')
	for sublang_name in SUBLANG.get(sublang_value,[]):
		if lang_name in sublang_name:return sublang_name
	return SUBLANG.get(sublang_value,['*unknown*'])[0]
def parse_strings(data,counter,l):
	i=0;error_count=0
	while i<len(data):
		data_slice=data[i:i+2]
		if len(data_slice)<2:break
		len_=struct.unpack('<h',data_slice)[0];i+=2
		if len_!=0 and 0<=len_*2<=len(data):
			try:l[counter]=data[i:i+len_*2].decode('utf-16le')
			except UnicodeDecodeError:error_count+=1
			if error_count>=3:break
			i+=len_*2
		counter+=1
def retrieve_flags(flag_dict,flag_filter):return[(flag,flag_dict[flag])for flag in flag_dict.keys()if isinstance(flag,(str,bytes))and flag.startswith(flag_filter)]
def set_flags(obj,flag_field,flags):
	for(flag,value)in flags:
		if value&flag_field:obj.__dict__[flag]=True
		else:obj.__dict__[flag]=False
def power_of_two(val):return val!=0 and val&val-1==0
class AddressSet(set):
	def __init__(self):super().__init__();self.min=None;self.max=None
	def add(self,value):super().add(value);self.min=value if self.min is None else min(self.min,value);self.max=value if self.max is None else max(self.max,value)
	def diff(self):return 0 if self.min is None or self.max is None else self.max-self.min
class UnicodeStringWrapperPostProcessor:
	def __init__(self,pe,rva_ptr):self.pe=pe;self.rva_ptr=rva_ptr;self.string=None
	def get_rva(self):return self.rva_ptr
	def __str__(self):return self.decode('utf-8','backslashreplace_')
	def decode(self,*args):
		if not self.string:return''
		return self.string.decode(*args)
	def invalidate(self):self=None
	def render_pascal_16(self):
		try:self.string=self.pe.get_string_u_at_rva(self.rva_ptr+2,max_length=self.get_pascal_16_length())
		except PEFormatError:self.pe.get_warnings().append('Failed rendering pascal string, attempting to read from RVA 0x{0:x}'.format(self.rva_ptr+2))
	def get_pascal_16_length(self):return self.__get_word_value_at_rva(self.rva_ptr)
	def __get_word_value_at_rva(self,rva):
		try:data=self.pe.get_data(rva,2)
		except PEFormatError:return False
		if len(data)<2:return False
		return struct.unpack('<H',data)[0]
	def ask_unicode_16(self,next_rva_ptr):
		if self.__get_word_value_at_rva(next_rva_ptr-2)==0:self.length=next_rva_ptr-self.rva_ptr;return True
		return False
	def render_unicode_16(self):
		try:self.string=self.pe.get_string_u_at_rva(self.rva_ptr)
		except PEFormatError:self.pe.get_warnings().append('Failed rendering unicode string, attempting to read from RVA 0x{0:x}'.format(self.rva_ptr))
class PEFormatError(Exception):
	def __init__(self,value):self.value=value
	def __str__(self):return repr(self.value)
class Dump:
	def __init__(self):self.text=[]
	def add_lines(self,txt,indent=0):
		for line in txt:self.add_line(line,indent)
	def add_line(self,txt,indent=0):self.add(txt+'\n',indent)
	def add(self,txt,indent=0):self.text.append('{0}{1}'.format(' '*indent,txt))
	def add_header(self,txt):self.add_line('{0}{1}{0}\n'.format('-'*10,txt))
	def add_newline(self):self.text.append('\n')
	def get_text(self):return''.join('{0}'.format(b)for b in self.text)
STRUCT_SIZEOF_TYPES={'x':1,'c':1,'b':1,'B':1,'h':2,'H':2,'i':4,'I':4,'l':4,'L':4,'f':4,'q':8,'Q':8,'d':8,'s':1}
@lru_cache(maxsize=2048)
def sizeof_type(t):
	count=1;_t=t
	if t[0]in string.digits:count=int(''.join([d for d in t if d in string.digits]));_t=''.join([d for d in t if d not in string.digits])
	return STRUCT_SIZEOF_TYPES[_t]*count
@lru_cache(maxsize=2048,copy=True)
def set_format(format):
	__format_str__='<';__unpacked_data_elms__=[];__field_offsets__={};__keys__=[];__format_length__=0;offset=0
	for elm in format:
		if','in elm:
			elm_type,elm_name=elm.split(',',1);__format_str__+=elm_type;__unpacked_data_elms__.append(None);elm_names=elm_name.split(',');names=[]
			for elm_name in elm_names:
				if elm_name in __keys__:search_list=[x[:len(elm_name)]for x in __keys__];occ_count=search_list.count(elm_name);elm_name='{0}_{1:d}'.format(elm_name,occ_count)
				names.append(elm_name);__field_offsets__[elm_name]=offset
			offset+=sizeof_type(elm_type);__keys__.append(names)
	__format_length__=struct.calcsize(__format_str__);return __format_str__,__unpacked_data_elms__,__field_offsets__,__keys__,__format_length__
class Structure:
	def __init__(self,format,name=None,file_offset=None):
		self.__format_str__='<';self.__keys__=[];self.__format_length__=0;self.__field_offsets__={};self.__unpacked_data_elms__=[];d=format[1]
		if not isinstance(d,tuple):d=tuple(d)
		self.__format_str__,self.__unpacked_data_elms__,self.__field_offsets__,self.__keys__,self.__format_length__=set_format(d);self.__all_zeroes__=False;self.__file_offset__=file_offset
		if name:self.name=name
		else:self.name=format[0]
	def __get_format__(self):return self.__format_str__
	def get_field_absolute_offset(self,field_name):return self.__file_offset__+self.__field_offsets__[field_name]
	def get_field_relative_offset(self,field_name):return self.__field_offsets__[field_name]
	def get_file_offset(self):return self.__file_offset__
	def set_file_offset(self,offset):self.__file_offset__=offset
	def all_zeroes(self):return self.__all_zeroes__
	def sizeof(self):return self.__format_length__
	def __unpack__(self,data):
		data=data
		if len(data)>self.__format_length__:data=data[:self.__format_length__]
		elif len(data)<self.__format_length__:raise PEFormatError('Data length less than expected header length.')
		if count_zeroes(data)==len(data):self.__all_zeroes__=True
		self.__unpacked_data_elms__=struct.unpack(self.__format_str__,data)
		for(idx,val)in enumerate(self.__unpacked_data_elms__):
			for key in self.__keys__[idx]:setattr(self,key,val)
	def __pack__(self):
		new_values=[]
		for(idx,val)in enumerate(self.__unpacked_data_elms__):
			new_val=None
			for key in self.__keys__[idx]:
				new_val=getattr(self,key)
				if new_val!=val:break
			new_values.append(new_val)
		return struct.pack(self.__format_str__,*new_values)
	def __str__(self):return'\n'.join(self.dump())
	def __repr__(self):return'<Structure: %s>'%' '.join([' '.join(s.split())for s in self.dump()])
	def dump(self,indentation=0):
		dump=[];dump.append('[{0}]'.format(self.name));printable_bytes=[ord(i)for i in string.printable if i not in string.whitespace]
		for keys in self.__keys__:
			for key in keys:
				val=getattr(self,key)
				if isinstance(val,(int,long)):
					if key.startswith('Signature_'):val_str='{:<8X}'.format(val)
					else:val_str='0x{:<8X}'.format(val)
					if key=='TimeDateStamp'or key=='dwTimeStamp':
						try:val_str+=' [%s UTC]'%time.asctime(time.gmtime(val))
						except ValueError:val_str+=' [INVALID TIME]'
				else:
					val_str=bytearray(val)
					if key.startswith('Signature'):val_str=''.join(['{:02X}'.format(i)for i in val_str.rstrip(b'\x00')])
					else:val_str=''.join([chr(i)if i in printable_bytes else'\\x{0:02x}'.format(i)for i in val_str.rstrip(b'\x00')])
				dump.append('0x%-8X 0x%-3X %-30s %s'%(self.__field_offsets__[key]+self.__file_offset__,self.__field_offsets__[key],key+':',val_str))
		return dump
	def dump_dict(self):
		dump_dict={};dump_dict['Structure']=self.name
		for keys in self.__keys__:
			for key in keys:
				val=getattr(self,key)
				if isinstance(val,(int,long)):
					if key=='TimeDateStamp'or key=='dwTimeStamp':
						try:val='0x%-8X [%s UTC]'%(val,time.asctime(time.gmtime(val)))
						except ValueError:val='0x%-8X [INVALID TIME]'%val
				else:val=''.join(chr(d)if chr(d)in string.printable else'\\x%02x'%d for d in[ord(c)if not isinstance(c,int)else c for c in val])
				dump_dict[key]={'FileOffset':self.__field_offsets__[key]+self.__file_offset__,'Offset':self.__field_offsets__[key],'Value':val}
		return dump_dict
class SectionStructure(Structure):
	def __init__(self,*args,**kwargs):
		if'pe'in kwargs:self.pe=kwargs['pe'];del kwargs['pe']
		self.PointerToRawData=None;self.VirtualAddress=None;self.SizeOfRawData=None;self.Misc_VirtualSize=None;super().__init__(*args,**kwargs);self.PointerToRawData_adj=None;self.VirtualAddress_adj=None;self.section_min_addr=None;self.section_max_addr=None
	def get_PointerToRawData_adj(self):
		if self.PointerToRawData_adj is None and self.PointerToRawData is not None:
			ptrd=self.pe.adjust_PointerToRawData(self.PointerToRawData)
			if self.pe.OPTIONAL_HEADER.SectionAlignment<4096:
				if self.PointerToRawData==self.VirtualAddress:ptrd=self.VirtualAddress
			self.PointerToRawData_adj=ptrd
		return self.PointerToRawData_adj
	def get_VirtualAddress_adj(self):
		if self.VirtualAddress_adj is None:
			if self.VirtualAddress is not None:self.VirtualAddress_adj=self.pe.adjust_SectionAlignment(self.VirtualAddress,self.pe.OPTIONAL_HEADER.SectionAlignment,self.pe.OPTIONAL_HEADER.FileAlignment)
		return self.VirtualAddress_adj
	def get_data(self,start=None,length=None,ignore_padding=False):
		if start is None:offset=self.get_PointerToRawData_adj()
		else:offset=start-self.get_VirtualAddress_adj()+self.get_PointerToRawData_adj()
		if length is not None:end=offset+length
		elif self.SizeOfRawData is not None:end=offset+self.SizeOfRawData
		else:end=offset
		if ignore_padding and end is not None and offset is not None:end=min(end,offset+self.Misc_VirtualSize)
		if self.PointerToRawData is not None and self.SizeOfRawData is not None:
			if end>self.PointerToRawData+self.SizeOfRawData:end=self.PointerToRawData+self.SizeOfRawData
		return self.pe.__data__[offset:end]
	def __setattr__(self,name,val):
		if name=='Characteristics':section_flags=retrieve_flags(SECTION_CHARACTERISTICS,'IMAGE_SCN_');set_flags(self,val,section_flags)
		elif'IMAGE_SCN_'in name and hasattr(self,name):
			if val:self.__dict__['Characteristics']|=SECTION_CHARACTERISTICS[name]
			else:self.__dict__['Characteristics']^=SECTION_CHARACTERISTICS[name]
		self.__dict__[name]=val
	def get_rva_from_offset(self,offset):return offset-self.get_PointerToRawData_adj()+self.get_VirtualAddress_adj()
	def get_offset_from_rva(self,rva):return rva-self.get_VirtualAddress_adj()+self.get_PointerToRawData_adj()
	def contains_offset(self,offset):
		if self.PointerToRawData is None:return False
		PointerToRawData_adj=self.get_PointerToRawData_adj();return PointerToRawData_adj<=offset<PointerToRawData_adj+self.SizeOfRawData
	def contains_rva(self,rva):
		if self.section_min_addr is not None and self.section_max_addr is not None:return self.section_min_addr<=rva<self.section_max_addr
		VirtualAddress_adj=self.get_VirtualAddress_adj()
		if len(self.pe.__data__)-self.get_PointerToRawData_adj()<self.SizeOfRawData:size=self.Misc_VirtualSize
		else:size=max(self.SizeOfRawData,self.Misc_VirtualSize)
		if self.next_section_virtual_address is not None and self.next_section_virtual_address>self.VirtualAddress and VirtualAddress_adj+size>self.next_section_virtual_address:size=self.next_section_virtual_address-VirtualAddress_adj
		self.section_min_addr=VirtualAddress_adj;self.section_max_addr=VirtualAddress_adj+size;return VirtualAddress_adj<=rva<VirtualAddress_adj+size
	def contains(self,rva):return self.contains_rva(rva)
	def get_entropy(self):return self.entropy_H(self.get_data())
	def get_hash_sha1(self):
		if sha1 is not None:return sha1(self.get_data()).hexdigest()
	def get_hash_sha256(self):
		if sha256 is not None:return sha256(self.get_data()).hexdigest()
	def get_hash_sha512(self):
		if sha512 is not None:return sha512(self.get_data()).hexdigest()
	def get_hash_md5(self):
		if md5 is not None:return md5(self.get_data()).hexdigest()
	def entropy_H(self,data):
		if not data:return .0
		occurences=Counter(bytearray(data));entropy=0
		for x in occurences.values():p_x=float(x)/len(data);entropy-=p_x*math.log(p_x,2)
		return entropy
@lru_cache(maxsize=2048,copy=False)
def set_bitfields_format(format):
	class Accumulator:
		def __init__(self,fmt,comp_fields):self._subfields=[];self._name='~';self._type=None;self._bits_left=0;self._comp_fields=comp_fields;self._format=fmt
		def wrap_up(self):
			if self._type is None:return
			self._format.append(self._type+','+self._name);self._comp_fields[len(self._format)-1]=self._type,self._subfields;self._name='~';self._type=None;self._subfields=[]
		def new_type(self,tp):self._bits_left=STRUCT_SIZEOF_TYPES[tp]*8;self._type=tp
		def add_subfield(self,name,bitcnt):self._name+=name;self._bits_left-=bitcnt;self._subfields.append((name,bitcnt))
		def get_type(self):return self._type
		def get_name(self):return self._name
		def get_bits_left(self):return self._bits_left
	old_fmt=[];comp_fields={};ac=Accumulator(old_fmt,comp_fields)
	for elm in format[1]:
		if':'not in elm:ac.wrap_up();old_fmt.append(elm);continue
		elm_type,elm_name=elm.split(',',1)
		if','in elm_name:raise NotImplementedError('Structures with bitfields do not support unions yet')
		elm_type,elm_bits=elm_type.split(':',1);elm_bits=int(elm_bits)
		if elm_type!=ac.get_type()or elm_bits>ac.get_bits_left():ac.wrap_up();ac.new_type(elm_type)
		ac.add_subfield(elm_name,elm_bits)
	ac.wrap_up();format_str,_,field_offsets,keys,format_length=set_format(tuple(old_fmt));extended_keys=[]
	for(idx,val)in enumerate(keys):
		if idx not in comp_fields:extended_keys.append(val);continue
		_,sbf=comp_fields[idx];bf_names=[[f[StructureWithBitfields.BTF_NAME_IDX]]for f in sbf];extended_keys.extend(bf_names)
		for n in bf_names:field_offsets[n[0]]=field_offsets[val[0]]
	return format_str,format_length,field_offsets,keys,extended_keys,comp_fields
class StructureWithBitfields(Structure):
	BTF_NAME_IDX=0;BTF_BITCNT_IDX=1;CF_TYPE_IDX=0;CF_SUBFLD_IDX=1
	def __init__(self,format,name=None,file_offset=None):self.__format_str__,self.__format_length__,self.__field_offsets__,self.__keys__,self.__keys_ext__,self.__compound_fields__=set_bitfields_format(format);self.__unpacked_data_elms__=[None for i in range(self.__format_length__)];self.__all_zeroes__=False;self.__file_offset__=file_offset;self.name=name if name!=None else format[0]
	def __unpack__(self,data):super().__unpack__(data);self._unpack_bitfield_attributes()
	def __pack__(self):
		self._pack_bitfield_attributes()
		try:data=super().__pack__()
		finally:self._unpack_bitfield_attributes()
		return data
	def dump(self,indentation=0):
		tk=self.__keys__;self.__keys__=self.__keys_ext__
		try:ret=super().dump(indentation)
		finally:self.__keys__=tk
		return ret
	def dump_dict(self):
		tk=self.__keys__;self.__keys__=self.__keys_ext__
		try:ret=super().dump_dict()
		finally:self.__keys__=tk
		return ret
	def _unpack_bitfield_attributes(self):
		for i in self.__compound_fields__.keys():
			cf_name=self.__keys__[i][0];cval=getattr(self,cf_name);delattr(self,cf_name);offst=0
			for sf in self.__compound_fields__[i][StructureWithBitfields.CF_SUBFLD_IDX]:mask=(1<<sf[StructureWithBitfields.BTF_BITCNT_IDX])-1;mask<<=offst;setattr(self,sf[StructureWithBitfields.BTF_NAME_IDX],(cval&mask)>>offst);offst+=sf[StructureWithBitfields.BTF_BITCNT_IDX]
	def _pack_bitfield_attributes(self):
		for i in self.__compound_fields__.keys():
			cf_name=self.__keys__[i][0];offst,acc_val=0,0
			for sf in self.__compound_fields__[i][StructureWithBitfields.CF_SUBFLD_IDX]:mask=(1<<sf[StructureWithBitfields.BTF_BITCNT_IDX])-1;field_val=getattr(self,sf[StructureWithBitfields.BTF_NAME_IDX])&mask;acc_val|=field_val<<offst;offst+=sf[StructureWithBitfields.BTF_BITCNT_IDX]
			setattr(self,cf_name,acc_val)
class DataContainer:
	def __init__(self,**kwargs):
		bare_setattr=super().__setattr__
		for(key,value)in kwargs.items():bare_setattr(key,value)
class ImportDescData(DataContainer):0
class ImportData(DataContainer):
	def __setattr__(self,name,val):
		if hasattr(self,'ordinal')and hasattr(self,'bound')and hasattr(self,'name'):
			if name=='ordinal':
				if self.pe.PE_TYPE==OPTIONAL_HEADER_MAGIC_PE:ordinal_flag=IMAGE_ORDINAL_FLAG
				elif self.pe.PE_TYPE==OPTIONAL_HEADER_MAGIC_PE_PLUS:ordinal_flag=IMAGE_ORDINAL_FLAG64
				self.struct_table.Ordinal=ordinal_flag|val&65535;self.struct_table.AddressOfData=self.struct_table.Ordinal;self.struct_table.Function=self.struct_table.Ordinal;self.struct_table.ForwarderString=self.struct_table.Ordinal
			elif name=='bound':
				if self.struct_iat is not None:self.struct_iat.AddressOfData=val;self.struct_iat.AddressOfData=self.struct_iat.AddressOfData;self.struct_iat.Function=self.struct_iat.AddressOfData;self.struct_iat.ForwarderString=self.struct_iat.AddressOfData
			elif name=='address':self.struct_table.AddressOfData=val;self.struct_table.Ordinal=self.struct_table.AddressOfData;self.struct_table.Function=self.struct_table.AddressOfData;self.struct_table.ForwarderString=self.struct_table.AddressOfData
			elif name=='name':
				if self.name_offset:
					name_rva=self.pe.get_rva_from_offset(self.name_offset);self.pe.set_dword_at_offset(self.ordinal_offset,0|name_rva)
					if len(val)>len(self.name):raise PEFormatError('The export name provided is longer than the existing one.')
					self.pe.set_bytes_at_offset(self.name_offset,val)
		self.__dict__[name]=val
class ExportDirData(DataContainer):0
class ExportData(DataContainer):
	def __setattr__(self,name,val):
		if hasattr(self,'ordinal')and hasattr(self,'address')and hasattr(self,'forwarder')and hasattr(self,'name'):
			if name=='ordinal':self.pe.set_word_at_offset(self.ordinal_offset,val)
			elif name=='address':self.pe.set_dword_at_offset(self.address_offset,val)
			elif name=='name':
				if len(val)>len(self.name):raise PEFormatError('The export name provided is longer than the existing one.')
				self.pe.set_bytes_at_offset(self.name_offset,val)
			elif name=='forwarder':
				if len(val)>len(self.forwarder):raise PEFormatError('The forwarder name provided is longer than the existing one.')
				self.pe.set_bytes_at_offset(self.forwarder_offset,val)
		self.__dict__[name]=val
class ResourceDirData(DataContainer):0
class ResourceDirEntryData(DataContainer):0
class ResourceDataEntryData(DataContainer):0
class DebugData(DataContainer):0
class DynamicRelocationData(DataContainer):0
class FunctionOverrideData(DataContainer):0
class FunctionOverrideDynamicRelocationData(DataContainer):0
class BddDynamicRelocationData(DataContainer):0
class BaseRelocationData(DataContainer):0
class RelocationData(DataContainer):
	def __setattr__(self,name,val):
		if hasattr(self,'struct'):
			word=self.struct.Data
			if name=='type':word=val<<12|word&4095
			elif name=='rva':offset=max(val-self.base_rva,0);word=word&61440|offset&4095
			self.struct.Data=word
		self.__dict__[name]=val
class TlsData(DataContainer):0
class BoundImportDescData(DataContainer):0
class LoadConfigData(DataContainer):0
class BoundImportRefData(DataContainer):0
class ExceptionsDirEntryData(DataContainer):0
class UnwindInfo(StructureWithBitfields):
	def __init__(self,file_offset=0):super().__init__(('UNWIND_INFO',('B:3,Version','B:5,Flags','B,SizeOfProlog','B,CountOfCodes','B:4,FrameRegister','B:4,FrameOffset')),file_offset=file_offset);self._full_size=super().sizeof();self._opt_field_name=None;self._code_info=StructureWithBitfields(('UNWIND_CODE',('B,CodeOffset','B:4,UnwindOp','B:4,OpInfo')),file_offset=0);self._chained_entry=None;self._finished_unpacking=False
	def unpack_in_stages(self,data):
		if self._finished_unpacking:return
		super().__unpack__(data);codes_cnt_max=self.CountOfCodes+1&~1;hdlr_offset=super().sizeof()+codes_cnt_max*self._code_info.sizeof();self._full_size=hdlr_offset+(0 if self.Flags==0 else STRUCT_SIZEOF_TYPES['I'])
		if len(data)<self._full_size:return
		if self.Version!=1 and self.Version!=2:return'Unsupported version of UNWIND_INFO at '+hex(self.__file_offset__)
		self.UnwindCodes=[];ro=super().sizeof();codes_left=self.CountOfCodes
		while codes_left>0:
			self._code_info.__unpack__(data[ro:ro+self._code_info.sizeof()]);ucode=PrologEpilogOpsFactory.create(self._code_info)
			if ucode is None:return'Unknown UNWIND_CODE at '+hex(self.__file_offset__+ro)
			len_in_codes=ucode.length_in_code_structures(self._code_info,self);opc_size=self._code_info.sizeof()*len_in_codes;ucode.initialize(self._code_info,data[ro:ro+opc_size],self,self.__file_offset__+ro);ro+=opc_size;codes_left-=len_in_codes;self.UnwindCodes.append(ucode)
		if self.UNW_FLAG_EHANDLER or self.UNW_FLAG_UHANDLER:self._opt_field_name='ExceptionHandler'
		if self.UNW_FLAG_CHAININFO:self._opt_field_name='FunctionEntry'
		if self._opt_field_name!=None:setattr(self,self._opt_field_name,struct.unpack('<I',data[hdlr_offset:hdlr_offset+STRUCT_SIZEOF_TYPES['I']])[0])
		self._finished_unpacking=True
	def dump(self,indentation=0):
		if self._opt_field_name!=None:self.__field_offsets__[self._opt_field_name]=self._full_size-STRUCT_SIZEOF_TYPES['I'];self.__keys_ext__.append([self._opt_field_name])
		try:dump=super().dump(indentation)
		finally:
			if self._opt_field_name!=None:self.__keys_ext__.pop()
		dump.append('Flags: '+', '.join([s[0]for s in unwind_info_flags if getattr(self,s[0])]));dump.append('Unwind codes: '+'; '.join([str(c)for c in self.UnwindCodes if c.is_valid()]));return dump
	def dump_dict(self):
		if self._opt_field_name!=None:self.__field_offsets__[self._opt_field_name]=self._full_size-STRUCT_SIZEOF_TYPES['I'];self.__keys_ext__.append([self._opt_field_name])
		try:ret=super().dump_dict()
		finally:
			if self._opt_field_name!=None:self.__keys_ext__.pop()
		return ret
	def __setattr__(self,name,val):
		if name=='Flags':set_flags(self,val,unwind_info_flags)
		elif'UNW_FLAG_'in name and hasattr(self,name):
			if val:self.__dict__['Flags']|=UNWIND_INFO_FLAGS[name]
			else:self.__dict__['Flags']^=UNWIND_INFO_FLAGS[name]
		self.__dict__[name]=val
	def sizeof(self):return self._full_size
	def __pack__(self):
		data=bytearray(self._full_size);data[0:super().sizeof()]=super().__pack__();cur_offset=super().sizeof()
		for uc in self.UnwindCodes:
			if cur_offset+uc.struct.sizeof()>self._full_size:break
			data[cur_offset:cur_offset+uc.struct.sizeof()]=uc.struct.__pack__();cur_offset+=uc.struct.sizeof()
		if self._opt_field_name!=None:data[self._full_size-STRUCT_SIZEOF_TYPES['I']:self._full_size]=struct.pack('<I',getattr(self,self._opt_field_name))
		return data
	def get_chained_function_entry(self):return self._chained_entry
	def set_chained_function_entry(self,entry):
		if self._chained_entry!=None:raise PEFormatError('Chained function entry cannot be changed')
		self._chained_entry=entry
class PrologEpilogOp:
	def initialize(self,unw_code,data,unw_info,file_offset):self.struct=StructureWithBitfields(self._get_format(unw_code),file_offset=file_offset);self.struct.__unpack__(data)
	def length_in_code_structures(self,unw_code,unw_info):return 1
	def is_valid(self):return True
	def _get_format(self,unw_code):return'UNWIND_CODE',('B,CodeOffset','B:4,UnwindOp','B:4,OpInfo')
class PrologEpilogOpPushReg(PrologEpilogOp):
	def _get_format(self,unw_code):return'UNWIND_CODE_PUSH_NONVOL',('B,CodeOffset','B:4,UnwindOp','B:4,Reg')
	def __str__(self):return'.PUSHREG '+REGISTERS[self.struct.Reg]
class PrologEpilogOpAllocLarge(PrologEpilogOp):
	def _get_format(self,unw_code):return'UNWIND_CODE_ALLOC_LARGE',('B,CodeOffset','B:4,UnwindOp','B:4,OpInfo','H,AllocSizeInQwords'if unw_code.OpInfo==0 else'I,AllocSize')
	def length_in_code_structures(self,unw_code,unw_info):return 2 if unw_code.OpInfo==0 else 3
	def get_alloc_size(self):return self.struct.AllocSizeInQwords*8 if self.struct.OpInfo==0 else self.struct.AllocSize
	def __str__(self):return'.ALLOCSTACK '+hex(self.get_alloc_size())
class PrologEpilogOpAllocSmall(PrologEpilogOp):
	def _get_format(self,unw_code):return'UNWIND_CODE_ALLOC_SMALL',('B,CodeOffset','B:4,UnwindOp','B:4,AllocSizeInQwordsMinus8')
	def get_alloc_size(self):return self.struct.AllocSizeInQwordsMinus8*8+8
	def __str__(self):return'.ALLOCSTACK '+hex(self.get_alloc_size())
class PrologEpilogOpSetFP(PrologEpilogOp):
	def initialize(self,unw_code,data,unw_info,file_offset):super().initialize(unw_code,data,unw_info,file_offset);self._frame_register=unw_info.FrameRegister;self._frame_offset=unw_info.FrameOffset*16
	def __str__(self):return'.SETFRAME '+REGISTERS[self._frame_register]+', '+hex(self._frame_offset)
class PrologEpilogOpSaveReg(PrologEpilogOp):
	def length_in_code_structures(self,unwcode,unw_info):return 2
	def get_offset(self):return self.struct.OffsetInQwords*8
	def _get_format(self,unw_code):return'UNWIND_CODE_SAVE_NONVOL',('B,CodeOffset','B:4,UnwindOp','B:4,Reg','H,OffsetInQwords')
	def __str__(self):return'.SAVEREG '+REGISTERS[self.struct.Reg]+', '+hex(self.get_offset())
class PrologEpilogOpSaveRegFar(PrologEpilogOp):
	def length_in_code_structures(self,unw_code,unw_info):return 3
	def get_offset(self):return self.struct.Offset
	def _get_format(self,unw_code):return'UNWIND_CODE_SAVE_NONVOL_FAR',('B,CodeOffset','B:4,UnwindOp','B:4,Reg','I,Offset')
	def __str__(self):return'.SAVEREG '+REGISTERS[self.struct.Reg]+', '+hex(self.struct.Offset)
class PrologEpilogOpSaveXMM(PrologEpilogOp):
	def _get_format(self,unw_code):return'UNWIND_CODE_SAVE_XMM128',('B,CodeOffset','B:4,UnwindOp','B:4,Reg','H,OffsetIn2Qwords')
	def length_in_code_structures(self,unw_code,unw_info):return 2
	def get_offset(self):return self.struct.OffsetIn2Qwords*16
	def __str__(self):return'.SAVEXMM128 XMM'+str(self.struct.Reg)+', '+hex(self.get_offset())
class PrologEpilogOpSaveXMMFar(PrologEpilogOp):
	def _get_format(self,unw_code):return'UNWIND_CODE_SAVE_XMM128_FAR',('B,CodeOffset','B:4,UnwindOp','B:4,Reg','I,Offset')
	def length_in_code_structures(self,unw_code,unw_info):return 3
	def get_offset(self):return self.struct.Offset
	def __str__(self):return'.SAVEXMM128 XMM'+str(self.struct.Reg)+', '+hex(self.struct.Offset)
class PrologEpilogOpPushFrame(PrologEpilogOp):
	def __str__(self):return'.PUSHFRAME'+(' <code>'if self.struct.OpInfo else'')
class PrologEpilogOpEpilogMarker(PrologEpilogOp):
	def initialize(self,unw_code,data,unw_info,file_offset):
		self._long_offst=True;self._first=not hasattr(unw_info,'SizeOfEpilog');super().initialize(unw_code,data,unw_info,file_offset)
		if self._first:setattr(unw_info,'SizeOfEpilog',self.struct.Size);self._long_offst=unw_code.OpInfo&1==0
		self._epilog_size=unw_info.SizeOfEpilog
	def _get_format(self,unw_code):
		if self._first:return'UNWIND_CODE_EPILOG',('B,OffsetLow,Size','B:4,UnwindOp','B:4,Flags')if unw_code.OpInfo&1==1 else('B,Size','B:4,UnwindOp','B:4,Flags','B,OffsetLow','B:4,Unused','B:4,OffsetHigh')
		else:return'UNWIND_CODE_EPILOG',('B,OffsetLow','B:4,UnwindOp','B:4,OffsetHigh')
	def length_in_code_structures(self,unw_code,unw_info):return 2 if not hasattr(unw_info,'SizeOfEpilog')and unw_code.OpInfo&1==0 else 1
	def get_offset(self):return self.struct.OffsetLow|(self.struct.OffsetHigh<<8 if self._long_offst else 0)
	def is_valid(self):return self.get_offset()>0
	def __str__(self):return'EPILOG: size='+hex(self._epilog_size)+', offset from the end=-'+hex(self.get_offset())if self.get_offset()>0 else''
class PrologEpilogOpsFactory:
	_class_dict={UWOP_PUSH_NONVOL:PrologEpilogOpPushReg,UWOP_ALLOC_LARGE:PrologEpilogOpAllocLarge,UWOP_ALLOC_SMALL:PrologEpilogOpAllocSmall,UWOP_SET_FPREG:PrologEpilogOpSetFP,UWOP_SAVE_NONVOL:PrologEpilogOpSaveReg,UWOP_SAVE_NONVOL_FAR:PrologEpilogOpSaveRegFar,UWOP_SAVE_XMM128:PrologEpilogOpSaveXMM,UWOP_SAVE_XMM128_FAR:PrologEpilogOpSaveXMMFar,UWOP_PUSH_MACHFRAME:PrologEpilogOpPushFrame,UWOP_EPILOG:PrologEpilogOpEpilogMarker}
	@staticmethod
	def create(unwcode):code=unwcode.UnwindOp;return PrologEpilogOpsFactory._class_dict[code]()if code in PrologEpilogOpsFactory._class_dict else None
allowed_filename=(string.ascii_lowercase+string.ascii_uppercase+string.digits+"!#$%&'()-@^_`{}~+,.;=[]:").encode()
def is_valid_dos_filename(s):
	if s is None or not isinstance(s,(str,bytes,bytearray)):return False
	allowed=allowed_filename+b'\\/';return all(c in allowed for c in set(s))
allowed_function_name=(string.ascii_lowercase+string.ascii_uppercase+string.digits).encode()
@lru_cache(maxsize=2048)
def is_valid_function_name(s,relax_allowed_characters=False):
	allowed_extra=b'._?@$()<>'
	if relax_allowed_characters:allowed_extra=b'!"#$%&\'()*+,-./:<>?[\\]^_`{|}~@'
	return s is not None and isinstance(s,(str,bytes,bytearray))and all(c in allowed_function_name or c in allowed_extra for c in set(s))
class PE:
	__IMAGE_DOS_HEADER_format__='IMAGE_DOS_HEADER',('H,e_magic','H,e_cblp','H,e_cp','H,e_crlc','H,e_cparhdr','H,e_minalloc','H,e_maxalloc','H,e_ss','H,e_sp','H,e_csum','H,e_ip','H,e_cs','H,e_lfarlc','H,e_ovno','8s,e_res','H,e_oemid','H,e_oeminfo','20s,e_res2','I,e_lfanew');__IMAGE_FILE_HEADER_format__='IMAGE_FILE_HEADER',('H,Machine','H,NumberOfSections','I,TimeDateStamp','I,PointerToSymbolTable','I,NumberOfSymbols','H,SizeOfOptionalHeader','H,Characteristics');__IMAGE_DATA_DIRECTORY_format__='IMAGE_DATA_DIRECTORY',('I,VirtualAddress','I,Size');__IMAGE_OPTIONAL_HEADER_format__='IMAGE_OPTIONAL_HEADER',('H,Magic','B,MajorLinkerVersion','B,MinorLinkerVersion','I,SizeOfCode','I,SizeOfInitializedData','I,SizeOfUninitializedData','I,AddressOfEntryPoint','I,BaseOfCode','I,BaseOfData','I,ImageBase','I,SectionAlignment','I,FileAlignment','H,MajorOperatingSystemVersion','H,MinorOperatingSystemVersion','H,MajorImageVersion','H,MinorImageVersion','H,MajorSubsystemVersion','H,MinorSubsystemVersion','I,Reserved1','I,SizeOfImage','I,SizeOfHeaders','I,CheckSum','H,Subsystem','H,DllCharacteristics','I,SizeOfStackReserve','I,SizeOfStackCommit','I,SizeOfHeapReserve','I,SizeOfHeapCommit','I,LoaderFlags','I,NumberOfRvaAndSizes');__IMAGE_OPTIONAL_HEADER64_format__='IMAGE_OPTIONAL_HEADER64',('H,Magic','B,MajorLinkerVersion','B,MinorLinkerVersion','I,SizeOfCode','I,SizeOfInitializedData','I,SizeOfUninitializedData','I,AddressOfEntryPoint','I,BaseOfCode','Q,ImageBase','I,SectionAlignment','I,FileAlignment','H,MajorOperatingSystemVersion','H,MinorOperatingSystemVersion','H,MajorImageVersion','H,MinorImageVersion','H,MajorSubsystemVersion','H,MinorSubsystemVersion','I,Reserved1','I,SizeOfImage','I,SizeOfHeaders','I,CheckSum','H,Subsystem','H,DllCharacteristics','Q,SizeOfStackReserve','Q,SizeOfStackCommit','Q,SizeOfHeapReserve','Q,SizeOfHeapCommit','I,LoaderFlags','I,NumberOfRvaAndSizes');__IMAGE_NT_HEADERS_format__='IMAGE_NT_HEADERS',('I,Signature',);__IMAGE_SECTION_HEADER_format__='IMAGE_SECTION_HEADER',('8s,Name','I,Misc,Misc_PhysicalAddress,Misc_VirtualSize','I,VirtualAddress','I,SizeOfRawData','I,PointerToRawData','I,PointerToRelocations','I,PointerToLinenumbers','H,NumberOfRelocations','H,NumberOfLinenumbers','I,Characteristics');__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__='IMAGE_DELAY_IMPORT_DESCRIPTOR',('I,grAttrs','I,szName','I,phmod','I,pIAT','I,pINT','I,pBoundIAT','I,pUnloadIAT','I,dwTimeStamp');__IMAGE_IMPORT_DESCRIPTOR_format__='IMAGE_IMPORT_DESCRIPTOR',('I,OriginalFirstThunk,Characteristics','I,TimeDateStamp','I,ForwarderChain','I,Name','I,FirstThunk');__IMAGE_EXPORT_DIRECTORY_format__='IMAGE_EXPORT_DIRECTORY',('I,Characteristics','I,TimeDateStamp','H,MajorVersion','H,MinorVersion','I,Name','I,Base','I,NumberOfFunctions','I,NumberOfNames','I,AddressOfFunctions','I,AddressOfNames','I,AddressOfNameOrdinals');__IMAGE_RESOURCE_DIRECTORY_format__='IMAGE_RESOURCE_DIRECTORY',('I,Characteristics','I,TimeDateStamp','H,MajorVersion','H,MinorVersion','H,NumberOfNamedEntries','H,NumberOfIdEntries');__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__='IMAGE_RESOURCE_DIRECTORY_ENTRY',('I,Name','I,OffsetToData');__IMAGE_RESOURCE_DATA_ENTRY_format__='IMAGE_RESOURCE_DATA_ENTRY',('I,OffsetToData','I,Size','I,CodePage','I,Reserved');__VS_VERSIONINFO_format__='VS_VERSIONINFO',('H,Length','H,ValueLength','H,Type');__VS_FIXEDFILEINFO_format__='VS_FIXEDFILEINFO',('I,Signature','I,StrucVersion','I,FileVersionMS','I,FileVersionLS','I,ProductVersionMS','I,ProductVersionLS','I,FileFlagsMask','I,FileFlags','I,FileOS','I,FileType','I,FileSubtype','I,FileDateMS','I,FileDateLS');__StringFileInfo_format__='StringFileInfo',('H,Length','H,ValueLength','H,Type');__StringTable_format__='StringTable',('H,Length','H,ValueLength','H,Type');__String_format__='String',('H,Length','H,ValueLength','H,Type');__Var_format__='Var',('H,Length','H,ValueLength','H,Type');__IMAGE_THUNK_DATA_format__='IMAGE_THUNK_DATA',('I,ForwarderString,Function,Ordinal,AddressOfData',);__IMAGE_THUNK_DATA64_format__='IMAGE_THUNK_DATA',('Q,ForwarderString,Function,Ordinal,AddressOfData',);__IMAGE_DEBUG_DIRECTORY_format__='IMAGE_DEBUG_DIRECTORY',('I,Characteristics','I,TimeDateStamp','H,MajorVersion','H,MinorVersion','I,Type','I,SizeOfData','I,AddressOfRawData','I,PointerToRawData');__IMAGE_BASE_RELOCATION_format__='IMAGE_BASE_RELOCATION',('I,VirtualAddress','I,SizeOfBlock');__IMAGE_BASE_RELOCATION_ENTRY_format__='IMAGE_BASE_RELOCATION_ENTRY',('H,Data',);__IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format__='IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION',('I:12,PageRelativeOffset','I:1,IndirectCall','I:19,IATIndex');__IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format__='IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION',('H:12,PageRelativeOffset','H:1,IndirectCall','H:1,RexWPrefix','H:1,CfgCheck','H:1,Reserved');__IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION_format__='IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION',('H:12,PageRelativeOffset','H:4,RegisterNumber');__IMAGE_FUNCTION_OVERRIDE_HEADER_format__='IMAGE_FUNCTION_OVERRIDE_HEADER',('I,FuncOverrideSize',);__IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION_format__='IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION',('I,OriginalRva','I,BDDOffset','I,RvaSize','I,BaseRelocSize');__IMAGE_BDD_INFO_format__='IMAGE_BDD_INFO',('I,Version','I,BDDSize');__IMAGE_BDD_DYNAMIC_RELOCATION_format__='IMAGE_BDD_DYNAMIC_RELOCATION',('H,Left','H,Right','I,Value');__IMAGE_TLS_DIRECTORY_format__='IMAGE_TLS_DIRECTORY',('I,StartAddressOfRawData','I,EndAddressOfRawData','I,AddressOfIndex','I,AddressOfCallBacks','I,SizeOfZeroFill','I,Characteristics');__IMAGE_TLS_DIRECTORY64_format__='IMAGE_TLS_DIRECTORY',('Q,StartAddressOfRawData','Q,EndAddressOfRawData','Q,AddressOfIndex','Q,AddressOfCallBacks','I,SizeOfZeroFill','I,Characteristics');__IMAGE_LOAD_CONFIG_DIRECTORY_format__='IMAGE_LOAD_CONFIG_DIRECTORY',('I,Size','I,TimeDateStamp','H,MajorVersion','H,MinorVersion','I,GlobalFlagsClear','I,GlobalFlagsSet','I,CriticalSectionDefaultTimeout','I,DeCommitFreeBlockThreshold','I,DeCommitTotalFreeThreshold','I,LockPrefixTable','I,MaximumAllocationSize','I,VirtualMemoryThreshold','I,ProcessHeapFlags','I,ProcessAffinityMask','H,CSDVersion','H,DependentLoadFlags','I,EditList','I,SecurityCookie','I,SEHandlerTable','I,SEHandlerCount','I,GuardCFCheckFunctionPointer','I,GuardCFDispatchFunctionPointer','I,GuardCFFunctionTable','I,GuardCFFunctionCount','I,GuardFlags','H,CodeIntegrityFlags','H,CodeIntegrityCatalog','I,CodeIntegrityCatalogOffset','I,CodeIntegrityReserved','I,GuardAddressTakenIatEntryTable','I,GuardAddressTakenIatEntryCount','I,GuardLongJumpTargetTable','I,GuardLongJumpTargetCount','I,DynamicValueRelocTable','I,CHPEMetadataPointer','I,GuardRFFailureRoutine','I,GuardRFFailureRoutineFunctionPointer','I,DynamicValueRelocTableOffset','H,DynamicValueRelocTableSection','H,Reserved2','I,GuardRFVerifyStackPointerFunctionPointer','I,HotPatchTableOffset','I,Reserved3','I,EnclaveConfigurationPointer','I,VolatileMetadataPointer','I,GuardEHContinuationTable','I,GuardEHContinuationCount','I,GuardXFGCheckFunctionPointer','I,GuardXFGDispatchFunctionPointer','I,GuardXFGTableDispatchFunctionPointer','I,CastGuardOsDeterminedFailureMode','I,GuardMemcpyFunctionPointer');__IMAGE_LOAD_CONFIG_DIRECTORY64_format__='IMAGE_LOAD_CONFIG_DIRECTORY',('I,Size','I,TimeDateStamp','H,MajorVersion','H,MinorVersion','I,GlobalFlagsClear','I,GlobalFlagsSet','I,CriticalSectionDefaultTimeout','Q,DeCommitFreeBlockThreshold','Q,DeCommitTotalFreeThreshold','Q,LockPrefixTable','Q,MaximumAllocationSize','Q,VirtualMemoryThreshold','Q,ProcessAffinityMask','I,ProcessHeapFlags','H,CSDVersion','H,DependentLoadFlags','Q,EditList','Q,SecurityCookie','Q,SEHandlerTable','Q,SEHandlerCount','Q,GuardCFCheckFunctionPointer','Q,GuardCFDispatchFunctionPointer','Q,GuardCFFunctionTable','Q,GuardCFFunctionCount','I,GuardFlags','H,CodeIntegrityFlags','H,CodeIntegrityCatalog','I,CodeIntegrityCatalogOffset','I,CodeIntegrityReserved','Q,GuardAddressTakenIatEntryTable','Q,GuardAddressTakenIatEntryCount','Q,GuardLongJumpTargetTable','Q,GuardLongJumpTargetCount','Q,DynamicValueRelocTable','Q,CHPEMetadataPointer','Q,GuardRFFailureRoutine','Q,GuardRFFailureRoutineFunctionPointer','I,DynamicValueRelocTableOffset','H,DynamicValueRelocTableSection','H,Reserved2','Q,GuardRFVerifyStackPointerFunctionPointer','I,HotPatchTableOffset','I,Reserved3','Q,EnclaveConfigurationPointer','Q,VolatileMetadataPointer','Q,GuardEHContinuationTable','Q,GuardEHContinuationCount','Q,GuardXFGCheckFunctionPointer','Q,GuardXFGDispatchFunctionPointer','Q,GuardXFGTableDispatchFunctionPointer','Q,CastGuardOsDeterminedFailureMode','Q,GuardMemcpyFunctionPointer');__IMAGE_DYNAMIC_RELOCATION_TABLE_format__='IMAGE_DYNAMIC_RELOCATION_TABLE',('I,Version','I,Size');__IMAGE_DYNAMIC_RELOCATION_format__='IMAGE_DYNAMIC_RELOCATION',('I,Symbol','I,BaseRelocSize');__IMAGE_DYNAMIC_RELOCATION64_format__='IMAGE_DYNAMIC_RELOCATION64',('Q,Symbol','I,BaseRelocSize');__IMAGE_DYNAMIC_RELOCATION_V2_format__='IMAGE_DYNAMIC_RELOCATION_V2',('I,HeaderSize','I,FixupInfoSize','I,Symbol','I,SymbolGroup','I,Flags');__IMAGE_DYNAMIC_RELOCATION64_V2_format__='IMAGE_DYNAMIC_RELOCATION64_V2',('I,HeaderSize','I,FixupInfoSize','Q,Symbol','I,SymbolGroup','I,Flags');__IMAGE_BOUND_IMPORT_DESCRIPTOR_format__='IMAGE_BOUND_IMPORT_DESCRIPTOR',('I,TimeDateStamp','H,OffsetModuleName','H,NumberOfModuleForwarderRefs');__IMAGE_BOUND_FORWARDER_REF_format__='IMAGE_BOUND_FORWARDER_REF',('I,TimeDateStamp','H,OffsetModuleName','H,Reserved');__RUNTIME_FUNCTION_format__='RUNTIME_FUNCTION',('I,BeginAddress','I,EndAddress','I,UnwindData')
	def __init__(self,name=None,data=None,fast_load=None,max_symbol_exports=MAX_SYMBOL_EXPORT_COUNT,max_repeated_symbol=120):
		self.max_symbol_exports=max_symbol_exports;self.max_repeated_symbol=max_repeated_symbol;self._get_section_by_rva_last_used=None;self.sections=[];self.__warnings=[];self.PE_TYPE=None
		if name is None and data is None:raise ValueError('Must supply either name or data')
		self.__structures__=[];self.__from_file=None;self.FileAlignment_Warning=False;self.SectionAlignment_Warning=False;self.__total_resource_entries_count=0;self.__total_resource_bytes=0;self.__total_import_symbols=0;self.dynamic_relocation_format_by_symbol={3:PE.__IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format__,4:PE.__IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format__,5:PE.__IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION_format__};fast_load=fast_load if fast_load is not None else globals()['fast_load']
		try:self.__parse__(name,data,fast_load)
		except:self.close();raise
	def __enter__(self):return self
	def __exit__(self,type,value,traceback):self.close()
	def _close_data(self):
		if self.__from_file is True and hasattr(self,'__data__')and(isinstance(mmap.mmap,type)and isinstance(self.__data__,mmap.mmap)or'mmap.mmap'in repr(type(self.__data__))):self.__data__.close();del self.__data__
		gc.collect()
	def close(self):self._close_data()
	def __unpack_data__(self,format,data,file_offset):
		structure=Structure(format,file_offset=file_offset)
		try:structure.__unpack__(data)
		except PEFormatError as err:self.__warnings.append('Corrupt header "{0}" at file offset {1}. Exception: {2}'.format(format[0],file_offset,err));return
		self.__structures__.append(structure);return structure
	def __unpack_data_with_bitfields__(self,format,data,file_offset):
		structure=StructureWithBitfields(format,file_offset=file_offset)
		try:structure.__unpack__(data)
		except PEFormatError as err:self.__warnings.append('Corrupt header "{0}" at file offset {1}. Exception: {2}'.format(format[0],file_offset,err));return
		self.__structures__.append(structure);return structure
	def __parse__(self,fname,data,fast_load):
		if fname is not None:
			stat=os.stat(fname)
			if stat.st_size==0:raise PEFormatError('The file is empty')
			fd=None
			try:
				fd=open(fname,'rb');self.fileno=fd.fileno()
				if hasattr(mmap,'MAP_PRIVATE'):self.__data__=mmap.mmap(self.fileno,0,mmap.MAP_PRIVATE)
				else:self.__data__=mmap.mmap(self.fileno,0,access=mmap.ACCESS_READ)
				self.__from_file=True
			except IOError as excp:exception_msg='{0}'.format(excp);exception_msg=exception_msg and': %s'%exception_msg;raise Exception("Unable to access file '{0}'{1}".format(fname,exception_msg))
			finally:
				if fd is not None:fd.close()
		elif data is not None:self.__data__=data;self.__from_file=False
		self.__resource_size_limit_upperbounds=len(self.__data__);self.__resource_size_limit_reached=False
		if not fast_load:
			for(byte,byte_count)in Counter(bytearray(self.__data__)).items():
				if byte==0 and byte_count/len(self.__data__)>.5 or byte!=0 and byte_count/len(self.__data__)>.15:self.__warnings.append("Byte 0x{0:02x} makes up {1:.4f}% of the file's contents. This may indicate truncation / malformation.".format(byte,1e2*byte_count/len(self.__data__)))
		dos_header_data=self.__data__[:64]
		if len(dos_header_data)!=64:raise PEFormatError('Unable to read the DOS Header, possibly a truncated file.')
		self.DOS_HEADER=self.__unpack_data__(self.__IMAGE_DOS_HEADER_format__,dos_header_data,file_offset=0)
		if self.DOS_HEADER.e_magic==IMAGE_DOSZM_SIGNATURE:raise PEFormatError('Probably a ZM Executable (not a PE file).')
		if not self.DOS_HEADER or self.DOS_HEADER.e_magic!=IMAGE_DOS_SIGNATURE:raise PEFormatError('DOS Header magic not found.')
		if self.DOS_HEADER.e_lfanew>len(self.__data__):raise PEFormatError('Invalid e_lfanew value, probably not a PE file')
		nt_headers_offset=self.DOS_HEADER.e_lfanew;self.NT_HEADERS=self.__unpack_data__(self.__IMAGE_NT_HEADERS_format__,self.__data__[nt_headers_offset:nt_headers_offset+8],file_offset=nt_headers_offset)
		if not self.NT_HEADERS or not self.NT_HEADERS.Signature:raise PEFormatError('NT Headers not found.')
		if 65535&self.NT_HEADERS.Signature==IMAGE_NE_SIGNATURE:raise PEFormatError('Invalid NT Headers signature. Probably a NE file')
		if 65535&self.NT_HEADERS.Signature==IMAGE_LE_SIGNATURE:raise PEFormatError('Invalid NT Headers signature. Probably a LE file')
		if 65535&self.NT_HEADERS.Signature==IMAGE_LX_SIGNATURE:raise PEFormatError('Invalid NT Headers signature. Probably a LX file')
		if 65535&self.NT_HEADERS.Signature==IMAGE_TE_SIGNATURE:raise PEFormatError('Invalid NT Headers signature. Probably a TE file')
		if self.NT_HEADERS.Signature!=IMAGE_NT_SIGNATURE:raise PEFormatError('Invalid NT Headers signature.')
		self.FILE_HEADER=self.__unpack_data__(self.__IMAGE_FILE_HEADER_format__,self.__data__[nt_headers_offset+4:nt_headers_offset+4+32],file_offset=nt_headers_offset+4);image_flags=retrieve_flags(IMAGE_CHARACTERISTICS,'IMAGE_FILE_')
		if not self.FILE_HEADER:raise PEFormatError('File Header missing')
		set_flags(self.FILE_HEADER,self.FILE_HEADER.Characteristics,image_flags);optional_header_offset=nt_headers_offset+4+self.FILE_HEADER.sizeof();sections_offset=optional_header_offset+self.FILE_HEADER.SizeOfOptionalHeader;self.OPTIONAL_HEADER=self.__unpack_data__(self.__IMAGE_OPTIONAL_HEADER_format__,self.__data__[optional_header_offset:optional_header_offset+256],file_offset=optional_header_offset);MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE=69
		if self.OPTIONAL_HEADER is None and len(self.__data__[optional_header_offset:optional_header_offset+512])>=MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE:padding_length=128;padded_data=self.__data__[optional_header_offset:optional_header_offset+512]+b'\x00'*padding_length;self.OPTIONAL_HEADER=self.__unpack_data__(self.__IMAGE_OPTIONAL_HEADER_format__,padded_data,file_offset=optional_header_offset)
		if self.OPTIONAL_HEADER is not None:
			if self.OPTIONAL_HEADER.Magic==OPTIONAL_HEADER_MAGIC_PE:self.PE_TYPE=OPTIONAL_HEADER_MAGIC_PE
			elif self.OPTIONAL_HEADER.Magic==OPTIONAL_HEADER_MAGIC_PE_PLUS:
				self.PE_TYPE=OPTIONAL_HEADER_MAGIC_PE_PLUS;self.OPTIONAL_HEADER=self.__unpack_data__(self.__IMAGE_OPTIONAL_HEADER64_format__,self.__data__[optional_header_offset:optional_header_offset+512],file_offset=optional_header_offset);MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE=73
				if self.OPTIONAL_HEADER is None and len(self.__data__[optional_header_offset:optional_header_offset+512])>=MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE:padding_length=128;padded_data=self.__data__[optional_header_offset:optional_header_offset+512]+b'\x00'*padding_length;self.OPTIONAL_HEADER=self.__unpack_data__(self.__IMAGE_OPTIONAL_HEADER64_format__,padded_data,file_offset=optional_header_offset)
		if not self.FILE_HEADER:raise PEFormatError('File Header missing')
		if self.OPTIONAL_HEADER is None:raise PEFormatError('No Optional Header found, invalid PE32 or PE32+ file.')
		if self.PE_TYPE is None:self.__warnings.append('Invalid type 0x{0:04x} in Optional Header.'.format(self.OPTIONAL_HEADER.Magic))
		dll_characteristics_flags=retrieve_flags(DLL_CHARACTERISTICS,'IMAGE_DLLCHARACTERISTICS_');set_flags(self.OPTIONAL_HEADER,self.OPTIONAL_HEADER.DllCharacteristics,dll_characteristics_flags);self.OPTIONAL_HEADER.DATA_DIRECTORY=[];offset=optional_header_offset+self.OPTIONAL_HEADER.sizeof();self.NT_HEADERS.FILE_HEADER=self.FILE_HEADER;self.NT_HEADERS.OPTIONAL_HEADER=self.OPTIONAL_HEADER
		if self.OPTIONAL_HEADER.AddressOfEntryPoint<self.OPTIONAL_HEADER.SizeOfHeaders:self.__warnings.append('SizeOfHeaders is smaller than AddressOfEntryPoint: this file cannot run under Windows 8.')
		if self.OPTIONAL_HEADER.NumberOfRvaAndSizes>16:self.__warnings.append('Suspicious NumberOfRvaAndSizes in the Optional Header. Normal values are never larger than 0x10, the value is: 0x%x'%self.OPTIONAL_HEADER.NumberOfRvaAndSizes)
		MAX_ASSUMED_VALID_NUMBER_OF_RVA_AND_SIZES=256
		for i in range(int(2147483647&self.OPTIONAL_HEADER.NumberOfRvaAndSizes)):
			if len(self.__data__)-offset==0:break
			if len(self.__data__)-offset<8:data=self.__data__[offset:]+b'\x00'*8
			else:data=self.__data__[offset:offset+MAX_ASSUMED_VALID_NUMBER_OF_RVA_AND_SIZES]
			dir_entry=self.__unpack_data__(self.__IMAGE_DATA_DIRECTORY_format__,data,file_offset=offset)
			if dir_entry is None:break
			try:dir_entry.name=DIRECTORY_ENTRY[i]
			except(KeyError,AttributeError):break
			offset+=dir_entry.sizeof();self.OPTIONAL_HEADER.DATA_DIRECTORY.append(dir_entry)
			if offset>=optional_header_offset+self.OPTIONAL_HEADER.sizeof()+128:break
		offset=self.parse_sections(sections_offset);rawDataPointers=[self.adjust_PointerToRawData(s.PointerToRawData)for s in self.sections if s.PointerToRawData>0]
		if len(rawDataPointers)>0:lowest_section_offset=min(rawDataPointers)
		else:lowest_section_offset=None
		if not lowest_section_offset or lowest_section_offset<offset:self.header=self.__data__[:offset]
		else:self.header=self.__data__[:lowest_section_offset]
		if self.get_section_by_rva(self.OPTIONAL_HEADER.AddressOfEntryPoint)is not None:
			ep_offset=self.get_offset_from_rva(self.OPTIONAL_HEADER.AddressOfEntryPoint)
			if ep_offset>len(self.__data__):self.__warnings.append('Possibly corrupt file. AddressOfEntryPoint lies outside the file. AddressOfEntryPoint: 0x%x'%self.OPTIONAL_HEADER.AddressOfEntryPoint)
		else:self.__warnings.append("AddressOfEntryPoint lies outside the sections' boundaries. AddressOfEntryPoint: 0x%x"%self.OPTIONAL_HEADER.AddressOfEntryPoint)
		if not fast_load:self.full_load()
	def parse_rich_header(self):
		DANS=1399742788;RICH=1751345490;rich_index=self.__data__.find(b'Rich',128,self.OPTIONAL_HEADER.get_file_offset())
		if rich_index==-1:return
		try:
			rich_data=self.__data__[128:rich_index+8];rich_data=rich_data[:4*(len(rich_data)//4)];data=list(struct.unpack('<{0}I'.format(len(rich_data)//4),rich_data))
			if RICH not in data:return
		except PEFormatError:return
		key=struct.pack('<L',data[data.index(RICH)+1]);result={'key':key};raw_data=rich_data[:rich_data.find(b'Rich')];result['raw_data']=raw_data;ord_=lambda c:ord(c)if not isinstance(c,int)else c;clear_data=bytearray()
		for(idx,val)in enumerate(raw_data):clear_data.append(ord_(val)^ord_(key[idx%len(key)]))
		result['clear_data']=bytes(clear_data);checksum=int.from_bytes(key,'little')
		if data[0]^checksum!=DANS or data[1]!=checksum or data[2]!=checksum or data[3]!=checksum:self.__warnings.append('Rich Header is not in Microsoft format, possibly malformed')
		result['checksum']=checksum;headervalues=[];result['values']=headervalues;data=data[4:]
		for i in range(len(data)//2):
			if data[2*i]==RICH:
				if data[2*i+1]!=checksum:self.__warnings.append('Rich Header is malformed')
				break
			headervalues+=[data[2*i]^checksum,data[2*i+1]^checksum]
		return result
	def get_warnings(self):return self.__warnings
	def show_warnings(self):
		for warning in self.__warnings:print('>',warning)
	def full_load(self):
		self.parse_data_directories()
		class RichHeader:0
		rich_header=self.parse_rich_header()
		if rich_header:self.RICH_HEADER=RichHeader();self.RICH_HEADER.checksum=rich_header.get('checksum',None);self.RICH_HEADER.values=rich_header.get('values',None);self.RICH_HEADER.key=rich_header.get('key',None);self.RICH_HEADER.raw_data=rich_header.get('raw_data',None);self.RICH_HEADER.clear_data=rich_header.get('clear_data',None)
		else:self.RICH_HEADER=None
	def write(self,filename=None):
		file_data=bytearray(self.__data__)
		for structure in self.__structures__:struct_data=bytearray(structure.__pack__());offset=structure.get_file_offset();file_data[offset:offset+len(struct_data)]=struct_data
		if hasattr(self,'VS_VERSIONINFO'):
			if hasattr(self,'FileInfo'):
				for finfo in self.FileInfo:
					for entry in finfo:
						if hasattr(entry,'StringTable'):
							for st_entry in entry.StringTable:
								for(key,entry)in list(st_entry.entries.items()):
									offsets=st_entry.entries_offsets[key];lengths=st_entry.entries_lengths[key]
									if len(entry)>lengths[1]:l=entry.decode('utf-8').encode('utf-16le');file_data[offsets[1]:offsets[1]+lengths[1]*2]=l[:lengths[1]*2]
									else:encoded_data=entry.decode('utf-8').encode('utf-16le');file_data[offsets[1]:offsets[1]+len(encoded_data)]=encoded_data
		new_file_data=file_data
		if not filename:return new_file_data
		with open(filename,'wb+')as f:f.write(new_file_data)
	def parse_sections(self,offset):
		self.sections=[];MAX_SIMULTANEOUS_ERRORS=3
		for i in range(self.FILE_HEADER.NumberOfSections):
			if i>=MAX_SECTIONS:self.__warnings.append('Too many sections {0} (>={1})'.format(self.FILE_HEADER.NumberOfSections,MAX_SECTIONS));break
			simultaneous_errors=0;section=SectionStructure(self.__IMAGE_SECTION_HEADER_format__,pe=self)
			if not section:break
			section_offset=offset+section.sizeof()*i;section.set_file_offset(section_offset);section_data=self.__data__[section_offset:section_offset+section.sizeof()]
			if count_zeroes(section_data)==section.sizeof():self.__warnings.append(f"Invalid section {i}. Contents are null-bytes.");break
			if not section_data:self.__warnings.append(f"Invalid section {i}. No data in the file (is this corkami's virtsectblXP?).");break
			section.__unpack__(section_data);self.__structures__.append(section)
			if section.SizeOfRawData+section.PointerToRawData>len(self.__data__):simultaneous_errors+=1;self.__warnings.append(f"Error parsing section {i}. SizeOfRawData is larger than file.")
			if self.adjust_PointerToRawData(section.PointerToRawData)>len(self.__data__):simultaneous_errors+=1;self.__warnings.append(f"Error parsing section {i}. PointerToRawData points beyond the end of the file.")
			if section.Misc_VirtualSize>268435456:simultaneous_errors+=1;self.__warnings.append(f"Suspicious value found parsing section {i}. VirtualSize is extremely large > 256MiB.")
			if self.adjust_SectionAlignment(section.VirtualAddress,self.OPTIONAL_HEADER.SectionAlignment,self.OPTIONAL_HEADER.FileAlignment)>268435456:simultaneous_errors+=1;self.__warnings.append(f"Suspicious value found parsing section {i}. VirtualAddress is beyond 0x10000000.")
			if self.OPTIONAL_HEADER.FileAlignment!=0 and section.PointerToRawData%self.OPTIONAL_HEADER.FileAlignment!=0:simultaneous_errors+=1;self.__warnings.append(f"Error parsing section {i}. PointerToRawData should normally be a multiple of FileAlignment, this might imply the file is trying to confuse tools which parse this incorrectly.")
			if simultaneous_errors>=MAX_SIMULTANEOUS_ERRORS:self.__warnings.append('Too many warnings parsing section. Aborting.');break
			section_flags=retrieve_flags(SECTION_CHARACTERISTICS,'IMAGE_SCN_');set_flags(section,section.Characteristics,section_flags)
			if section.__dict__.get('IMAGE_SCN_MEM_WRITE',False)and section.__dict__.get('IMAGE_SCN_MEM_EXECUTE',False):
				if section.Name.rstrip(b'\x00')==b'PAGE'and self.is_driver():0
				else:self.__warnings.append(f"Suspicious flags set for section {i}. Both IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE are set. This might indicate a packed executable.")
			self.sections.append(section)
		self.sections.sort(key=lambda a:a.VirtualAddress)
		for(idx,section)in enumerate(self.sections):
			if idx==len(self.sections)-1:section.next_section_virtual_address=None
			else:section.next_section_virtual_address=self.sections[idx+1].VirtualAddress
		if self.FILE_HEADER.NumberOfSections>0 and self.sections:return offset+self.sections[0].sizeof()*self.FILE_HEADER.NumberOfSections
		else:return offset
	def parse_data_directories(self,directories=None,forwarded_exports_only=False,import_dllnames_only=False):
		directory_parsing=('IMAGE_DIRECTORY_ENTRY_IMPORT',self.parse_import_directory),('IMAGE_DIRECTORY_ENTRY_EXPORT',self.parse_export_directory),('IMAGE_DIRECTORY_ENTRY_RESOURCE',self.parse_resources_directory),('IMAGE_DIRECTORY_ENTRY_DEBUG',self.parse_debug_directory),('IMAGE_DIRECTORY_ENTRY_BASERELOC',self.parse_relocations_directory),('IMAGE_DIRECTORY_ENTRY_TLS',self.parse_directory_tls),('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG',self.parse_directory_load_config),('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT',self.parse_delay_import_directory),('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT',self.parse_directory_bound_imports),('IMAGE_DIRECTORY_ENTRY_EXCEPTION',self.parse_exceptions_directory)
		if directories is not None:
			if not isinstance(directories,(tuple,list)):directories=[directories]
		for entry in directory_parsing:
			try:directory_index=DIRECTORY_ENTRY[entry[0]];dir_entry=self.OPTIONAL_HEADER.DATA_DIRECTORY[directory_index]
			except IndexError:break
			if directories is None or directory_index in directories:
				value=None
				if dir_entry.VirtualAddress:
					if forwarded_exports_only and entry[0]=='IMAGE_DIRECTORY_ENTRY_EXPORT':value=entry[1](dir_entry.VirtualAddress,dir_entry.Size,forwarded_only=True)
					elif import_dllnames_only and entry[0]=='IMAGE_DIRECTORY_ENTRY_IMPORT':value=entry[1](dir_entry.VirtualAddress,dir_entry.Size,dllnames_only=True)
					else:
						try:value=entry[1](dir_entry.VirtualAddress,dir_entry.Size)
						except PEFormatError as excp:self.__warnings.append(f'Failed to process directory "{entry[0]}": {excp}')
					if value:setattr(self,entry[0][6:],value)
			if directories is not None and isinstance(directories,list)and entry[0]in directories:directories.remove(directory_index)
	def parse_exceptions_directory(self,rva,size):
		if self.FILE_HEADER.Machine!=MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']and self.FILE_HEADER.Machine!=MACHINE_TYPE['IMAGE_FILE_MACHINE_IA64']:return
		rf=Structure(self.__RUNTIME_FUNCTION_format__);rf_size=rf.sizeof();rva2rt={};rt_funcs=[];rva2infos={}
		for _ in range(size//rf_size):
			rf=self.__unpack_data__(self.__RUNTIME_FUNCTION_format__,self.get_data(rva,rf_size),file_offset=self.get_offset_from_rva(rva))
			if rf is None:break
			ui=None
			if rf.UnwindData&1==0:
				if rf.UnwindData in rva2infos:ui=rva2infos[rf.UnwindData]
				else:ui=UnwindInfo(file_offset=self.get_offset_from_rva(rf.UnwindData));rva2infos[rf.UnwindData]=ui
				ws=ui.unpack_in_stages(self.get_data(rf.UnwindData,ui.sizeof()))
				if ws!=None:self.__warnings.append(ws);break
				ws=ui.unpack_in_stages(self.get_data(rf.UnwindData,ui.sizeof()))
				if ws!=None:self.__warnings.append(ws);break
				self.__structures__.append(ui)
			entry=ExceptionsDirEntryData(struct=rf,unwindinfo=ui);rt_funcs.append(entry);rva2rt[rf.BeginAddress]=entry;rva+=rf_size
		for rf in rt_funcs:
			if rf.unwindinfo is None:continue
			if not hasattr(rf.unwindinfo,'FunctionEntry'):continue
			if rf.unwindinfo.FunctionEntry not in rva2rt:self.__warnings.append(f"FunctionEntry of UNWIND_INFO at {rf.struct.get_file_offset():x} points to an entry that does not exist");continue
			try:rf.unwindinfo.set_chained_function_entry(rva2rt[rf.unwindinfo.FunctionEntry])
			except PEFormatError as excp:self.__warnings.append(f"Failed parsing FunctionEntry of UNWIND_INFO at {rf.struct.get_file_offset():x}: {excp}");continue
		return rt_funcs
	def parse_directory_bound_imports(self,rva,size):
		bnd_descr=Structure(self.__IMAGE_BOUND_IMPORT_DESCRIPTOR_format__);bnd_descr_size=bnd_descr.sizeof();start=rva;bound_imports=[]
		while True:
			bnd_descr=self.__unpack_data__(self.__IMAGE_BOUND_IMPORT_DESCRIPTOR_format__,self.__data__[rva:rva+bnd_descr_size],file_offset=rva)
			if bnd_descr is None:self.__warnings.append("The Bound Imports directory exists but can't be parsed.");return
			if bnd_descr.all_zeroes():break
			rva+=bnd_descr.sizeof();section=self.get_section_by_offset(rva);file_offset=self.get_offset_from_rva(rva)
			if section is None:
				safety_boundary=len(self.__data__)-file_offset;sections_after_offset=[s.PointerToRawData for s in self.sections if s.PointerToRawData>file_offset]
				if sections_after_offset:
					first_section_after_offset=min(sections_after_offset);section=self.get_section_by_offset(first_section_after_offset)
					if section is not None:safety_boundary=section.PointerToRawData-file_offset
			else:safety_boundary=section.PointerToRawData+len(section.get_data())-file_offset
			if not section:self.__warnings.append('RVA of IMAGE_BOUND_IMPORT_DESCRIPTOR points to an invalid address: {0:x}'.format(rva));return
			forwarder_refs=[]
			for _ in range(min(bnd_descr.NumberOfModuleForwarderRefs,int(safety_boundary/8))):
				bnd_frwd_ref=self.__unpack_data__(self.__IMAGE_BOUND_FORWARDER_REF_format__,self.__data__[rva:rva+bnd_descr_size],file_offset=rva)
				if not bnd_frwd_ref:raise PEFormatError('IMAGE_BOUND_FORWARDER_REF cannot be read')
				rva+=bnd_frwd_ref.sizeof();offset=start+bnd_frwd_ref.OffsetModuleName;name_str=self.get_string_from_data(0,self.__data__[offset:offset+MAX_STRING_LENGTH])
				if name_str:
					invalid_chars=[c for c in bytearray(name_str)if chr(c)not in string.printable]
					if len(name_str)>256 or invalid_chars:break
				forwarder_refs.append(BoundImportRefData(struct=bnd_frwd_ref,name=name_str))
			offset=start+bnd_descr.OffsetModuleName;name_str=self.get_string_from_data(0,self.__data__[offset:offset+MAX_STRING_LENGTH])
			if name_str:
				invalid_chars=[c for c in bytearray(name_str)if chr(c)not in string.printable]
				if len(name_str)>256 or invalid_chars:break
			if not name_str:break
			bound_imports.append(BoundImportDescData(struct=bnd_descr,name=name_str,entries=forwarder_refs))
		return bound_imports
	def parse_directory_tls(self,rva,size):
		format=self.__IMAGE_TLS_DIRECTORY_format__
		if self.PE_TYPE==OPTIONAL_HEADER_MAGIC_PE_PLUS:format=self.__IMAGE_TLS_DIRECTORY64_format__
		try:tls_struct=self.__unpack_data__(format,self.get_data(rva,Structure(format).sizeof()),file_offset=self.get_offset_from_rva(rva))
		except PEFormatError:self.__warnings.append("Invalid TLS information. Can't read data at RVA: 0x%x"%rva);tls_struct=None
		if not tls_struct:return
		return TlsData(struct=tls_struct)
	def parse_directory_load_config(self,rva,size):
		if self.PE_TYPE==OPTIONAL_HEADER_MAGIC_PE:load_config_dir_sz=self.get_dword_at_rva(rva);format=self.__IMAGE_LOAD_CONFIG_DIRECTORY_format__
		elif self.PE_TYPE==OPTIONAL_HEADER_MAGIC_PE_PLUS:load_config_dir_sz=self.get_dword_at_rva(rva);format=self.__IMAGE_LOAD_CONFIG_DIRECTORY64_format__
		else:self.__warnings.append("Don't know how to parse LOAD_CONFIG information for non-PE32/PE32+ file");return
		fields_counter=0;cumulative_sz=0
		for field in format[1]:
			fields_counter+=1;cumulative_sz+=STRUCT_SIZEOF_TYPES[field.split(',')[0]]
			if cumulative_sz==load_config_dir_sz:break
		format=format[0],format[1][:fields_counter];load_config_struct=None
		try:load_config_struct=self.__unpack_data__(format,self.get_data(rva,Structure(format).sizeof()),file_offset=self.get_offset_from_rva(rva))
		except PEFormatError:self.__warnings.append("Invalid LOAD_CONFIG information. Can't read data at RVA: 0x%x"%rva)
		if not load_config_struct:return
		dynamic_relocations=None
		if fields_counter>35:dynamic_relocations=self.parse_dynamic_relocations(load_config_struct.DynamicValueRelocTableOffset,load_config_struct.DynamicValueRelocTableSection)
		return LoadConfigData(struct=load_config_struct,dynamic_relocations=dynamic_relocations)
	def parse_dynamic_relocations(self,dynamic_value_reloc_table_offset,dynamic_value_reloc_table_section):
		if not dynamic_value_reloc_table_offset:return
		if not dynamic_value_reloc_table_section:return
		if dynamic_value_reloc_table_section>len(self.sections):return
		section=self.sections[dynamic_value_reloc_table_section-1];rva=section.VirtualAddress+dynamic_value_reloc_table_offset;image_dynamic_reloc_table_struct=None;reloc_table_size=Structure(self.__IMAGE_DYNAMIC_RELOCATION_TABLE_format__).sizeof()
		try:image_dynamic_reloc_table_struct=self.__unpack_data__(self.__IMAGE_DYNAMIC_RELOCATION_TABLE_format__,self.get_data(rva,reloc_table_size),file_offset=self.get_offset_from_rva(rva))
		except PEFormatError:self.__warnings.append("Invalid IMAGE_DYNAMIC_RELOCATION_TABLE information. Can't read data at RVA: 0x%x"%rva);return
		if image_dynamic_reloc_table_struct.Version!=1:self.__warnings.append('No parsing available for IMAGE_DYNAMIC_RELOCATION_TABLE.Version = %d'%image_dynamic_reloc_table_struct.Version);return
		rva+=reloc_table_size;end=rva+image_dynamic_reloc_table_struct.Size;dynamic_relocations=[]
		while rva<end:
			format=self.__IMAGE_DYNAMIC_RELOCATION_format__
			if self.PE_TYPE==OPTIONAL_HEADER_MAGIC_PE_PLUS:format=self.__IMAGE_DYNAMIC_RELOCATION64_format__
			rlc_size=Structure(format).sizeof()
			try:dynamic_rlc=self.__unpack_data__(format,self.get_data(rva,rlc_size),file_offset=self.get_offset_from_rva(rva))
			except PEFormatError:self.__warnings.append("Invalid relocation information. Can't read data at RVA: 0x%x"%rva);dynamic_rlc=None
			if not dynamic_rlc:break
			rva+=rlc_size;symbol=dynamic_rlc.Symbol;size=dynamic_rlc.BaseRelocSize
			if 3<=symbol<=5:relocations=self.parse_image_base_relocation_list(rva,size,self.dynamic_relocation_format_by_symbol[symbol]);dynamic_relocations.append(DynamicRelocationData(struct=dynamic_rlc,symbol=symbol,relocations=relocations))
			elif symbol==7:func_relocs,bdd_relocs=self.parse_function_override_data(rva);dynamic_relocations.append(FunctionOverrideData(struct=dynamic_rlc,symbol=symbol,bdd_relocs=bdd_relocs,func_relocs=func_relocs))
			elif symbol>5:relocations=self.parse_image_base_relocation_list(rva,size);dynamic_relocations.append(DynamicRelocationData(struct=dynamic_rlc,symbol=symbol,relocations=relocations))
			rva+=size
		return dynamic_relocations
	def parse_function_override_data(self,rva):
		func_relocs=[];bdd_relocs=[];format=self.__IMAGE_FUNCTION_OVERRIDE_HEADER_format__;func_header=self.__unpack_data__(format,self.get_data(rva,Structure(format).sizeof()),self.get_offset_from_rva(rva))
		if not func_header:self.__warnings.append("Invalid function override header. Can't read data at RVA: 0x%x"%rva);return func_relocs,bdd_relocs
		rva+=Structure(format).sizeof();func_end=rva+func_header.FuncOverrideSize
		while rva<func_end:
			format=self.__IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION_format__;func_info=self.__unpack_data__(format,self.get_data(rva,Structure(format).sizeof()),self.get_offset_from_rva(rva))
			if not func_info:self.__warnings.append("Invalid function override info. Can't read data at RVA: 0x%x"%rva);return func_relocs,bdd_relocs
			rva+=Structure(format).sizeof();override_rvas=[]
			for i in range(func_info.RvaSize//4):override_rvas.append(struct.unpack('<I',self.get_data(rva,4))[0]);rva+=4
			relocations=self.parse_image_base_relocation_list(rva,func_info.BaseRelocSize);rva+=func_info.BaseRelocSize;func_relocs.append(FunctionOverrideDynamicRelocationData(struct=func_info,func_rva=func_info.OriginalRva,override_rvas=override_rvas,relocations=relocations))
		format=self.__IMAGE_BDD_INFO_format__;bdd_info=self.__unpack_data__(format,self.get_data(rva,Structure(format).sizeof()),self.get_offset_from_rva(rva))
		if not bdd_info:self.__warnings.append("Invalid bdd info. Can't read data at RVA: 0x%x"%rva);return func_relocs,bdd_relocs
		rva+=Structure(format).sizeof()
		for i in range(bdd_info.BDDSize//8):
			format=self.__IMAGE_BDD_DYNAMIC_RELOCATION_format__;bdd_reloc=self.__unpack_data__(format,self.get_data(rva,Structure(format).sizeof()),self.get_offset_from_rva(rva))
			if not bdd_reloc:self.__warnings.append("Invalid bdd dynamic relocation. Can't read data at RVA: 0x%x"%rva);return func_relocs,bdd_relocs
			rva+=Structure(format).sizeof();bdd_relocs.append(BddDynamicRelocationData(struct=bdd_reloc))
		return func_relocs,bdd_relocs
	def parse_relocations_directory(self,rva,size):return self.parse_image_base_relocation_list(rva,size)
	def parse_image_base_relocation_list(self,rva,size,fmt=None):
		rlc_size=Structure(self.__IMAGE_BASE_RELOCATION_format__).sizeof();end=rva+size;relocations=[]
		while rva<end:
			try:rlc=self.__unpack_data__(self.__IMAGE_BASE_RELOCATION_format__,self.get_data(rva,rlc_size),file_offset=self.get_offset_from_rva(rva))
			except PEFormatError:self.__warnings.append("Invalid relocation information. Can't read data at RVA: 0x%x"%rva);rlc=None
			if not rlc:break
			if rlc.VirtualAddress>self.OPTIONAL_HEADER.SizeOfImage:self.__warnings.append('Invalid relocation information. VirtualAddress outside of Image: 0x%x'%rlc.VirtualAddress);break
			if rlc.SizeOfBlock>self.OPTIONAL_HEADER.SizeOfImage:self.__warnings.append('Invalid relocation information. SizeOfBlock too large: %d'%rlc.SizeOfBlock);break
			if fmt is None:reloc_entries=self.parse_relocations(rva+rlc_size,rlc.VirtualAddress,rlc.SizeOfBlock-rlc_size)
			else:reloc_entries=self.parse_relocations_with_format(rva+rlc_size,rlc.VirtualAddress,rlc.SizeOfBlock-rlc_size,fmt)
			relocations.append(BaseRelocationData(struct=rlc,entries=reloc_entries))
			if not rlc.SizeOfBlock:break
			rva+=rlc.SizeOfBlock
		return relocations
	def parse_relocations(self,data_rva,rva,size):
		try:data=self.get_data(data_rva,size);file_offset=self.get_offset_from_rva(data_rva)
		except PEFormatError:self.__warnings.append(f"Bad RVA in relocation data: 0x{data_rva:x}");return[]
		entries=[];offsets_and_type=set()
		for idx in range(len(data)//2):
			entry=self.__unpack_data__(self.__IMAGE_BASE_RELOCATION_ENTRY_format__,data[idx*2:(idx+1)*2],file_offset=file_offset)
			if not entry:break
			word=entry.Data;reloc_type=word>>12;reloc_offset=word&4095
			if(reloc_offset,reloc_type)in offsets_and_type:self.__warnings.append('Overlapping offsets in relocation data at RVA: 0x%x'%(reloc_offset+rva));break
			offsets_and_type.add((reloc_offset,reloc_type));entries.append(RelocationData(struct=entry,type=reloc_type,base_rva=rva,rva=reloc_offset+rva));file_offset+=entry.sizeof()
		return entries
	def parse_relocations_with_format(self,data_rva,rva,size,format):
		try:data=self.get_data(data_rva,size);file_offset=self.get_offset_from_rva(data_rva)
		except PEFormatError:self.__warnings.append(f"Bad RVA in relocation data: 0x{data_rva:x}");return[]
		entry_size=StructureWithBitfields(format).sizeof();entries=[];offsets=set()
		for idx in range(len(data)//entry_size):
			entry=self.__unpack_data_with_bitfields__(format,data[idx*entry_size:(idx+1)*entry_size],file_offset=file_offset)
			if not entry:break
			reloc_offset=entry.PageRelativeOffset
			if reloc_offset in offsets:self.__warnings.append('Overlapping offsets in relocation data at RVA: 0x%x'%(reloc_offset+rva));break
			offsets.add(reloc_offset);entries.append(RelocationData(struct=entry,base_rva=rva,rva=reloc_offset+rva));file_offset+=entry_size
		return entries
	def parse_debug_directory(self,rva,size):
		dbg_size=Structure(self.__IMAGE_DEBUG_DIRECTORY_format__).sizeof();debug=[]
		for idx in range(int(size/dbg_size)):
			try:data=self.get_data(rva+dbg_size*idx,dbg_size)
			except PEFormatError:self.__warnings.append("Invalid debug information. Can't read data at RVA: 0x%x"%rva);return
			dbg=self.__unpack_data__(self.__IMAGE_DEBUG_DIRECTORY_format__,data,file_offset=self.get_offset_from_rva(rva+dbg_size*idx))
			if not dbg:return
			dbg_type=None
			if dbg.Type==1:0
			elif dbg.Type==2:
				dbg_type_offset=dbg.PointerToRawData;dbg_type_size=dbg.SizeOfData;dbg_type_data=self.__data__[dbg_type_offset:dbg_type_offset+dbg_type_size]
				if dbg_type_data[:4]==b'RSDS':
					__CV_INFO_PDB70_format__=['CV_INFO_PDB70',['4s,CvSignature','I,Signature_Data1','H,Signature_Data2','H,Signature_Data3','B,Signature_Data4','B,Signature_Data5','6s,Signature_Data6','I,Age']];pdbFileName_size=dbg_type_size-Structure(__CV_INFO_PDB70_format__).sizeof()
					if pdbFileName_size>0:__CV_INFO_PDB70_format__[1].append('{0}s,PdbFileName'.format(pdbFileName_size))
					dbg_type=self.__unpack_data__(__CV_INFO_PDB70_format__,dbg_type_data,dbg_type_offset)
					if dbg_type is not None:dbg_type.Signature_Data6_value=struct.unpack('>Q',b'\x00\x00'+dbg_type.Signature_Data6)[0];dbg_type.Signature_String=str(uuid.UUID(fields=(dbg_type.Signature_Data1,dbg_type.Signature_Data2,dbg_type.Signature_Data3,dbg_type.Signature_Data4,dbg_type.Signature_Data5,dbg_type.Signature_Data6_value))).replace('-','').upper()+f"{dbg_type.Age:X}"
				elif dbg_type_data[:4]==b'NB10':
					__CV_INFO_PDB20_format__=['CV_INFO_PDB20',['I,CvHeaderSignature','I,CvHeaderOffset','I,Signature','I,Age']];pdbFileName_size=dbg_type_size-Structure(__CV_INFO_PDB20_format__).sizeof()
					if pdbFileName_size>0:__CV_INFO_PDB20_format__[1].append('{0}s,PdbFileName'.format(pdbFileName_size))
					dbg_type=self.__unpack_data__(__CV_INFO_PDB20_format__,dbg_type_data,dbg_type_offset)
			elif dbg.Type==4:
				dbg_type_offset=dbg.PointerToRawData;dbg_type_size=dbg.SizeOfData;dbg_type_data=self.__data__[dbg_type_offset:dbg_type_offset+dbg_type_size];___IMAGE_DEBUG_MISC_format__=['IMAGE_DEBUG_MISC',['I,DataType','I,Length','B,Unicode','B,Reserved1','H,Reserved2']];dbg_type_partial=self.__unpack_data__(___IMAGE_DEBUG_MISC_format__,dbg_type_data,dbg_type_offset)
				if dbg_type_partial:
					if dbg_type_partial.Unicode in(0,1):
						data_size=dbg_type_size-Structure(___IMAGE_DEBUG_MISC_format__).sizeof()
						if data_size>0:___IMAGE_DEBUG_MISC_format__[1].append('{0}s,Data'.format(data_size))
						dbg_type=self.__unpack_data__(___IMAGE_DEBUG_MISC_format__,dbg_type_data,dbg_type_offset)
			elif dbg.Type==20:dbg_type_offset=dbg.PointerToRawData;dbg_type_size=dbg.SizeOfData;dbg_type_data=self.__data__[dbg_type_offset:dbg_type_offset+dbg_type_size];___IMAGE_DEBUG_EX_DLLCHARACTERISTICS_format__=['IMAGE_DEBUG_EX_DLLCHARACTERISTICS',['I,ExDllCharacteristics']];dbg_type=self.__unpack_data__(___IMAGE_DEBUG_EX_DLLCHARACTERISTICS_format__,dbg_type_data,dbg_type_offset);ex_dll_characteristics_flags=retrieve_flags(EX_DLL_CHARACTERISTICS,'IMAGE_DLLCHARACTERISTICS_EX_');set_flags(dbg_type,dbg_type.ExDllCharacteristics,ex_dll_characteristics_flags)
			debug.append(DebugData(struct=dbg,entry=dbg_type))
		return debug
	def parse_resources_directory(self,rva,size=0,base_rva=None,level=0,dirs=None):
		if dirs is None:dirs=[rva]
		if base_rva is None:base_rva=rva
		if level>MAX_RESOURCE_DEPTH:self.__warnings.append('Error parsing the resources directory. Excessively nested table depth %d (>%s)'%(level,MAX_RESOURCE_DEPTH));return
		try:data=self.get_data(rva,Structure(self.__IMAGE_RESOURCE_DIRECTORY_format__).sizeof())
		except PEFormatError:self.__warnings.append("Invalid resources directory. Can't read directory data at RVA: 0x%x"%rva);return
		resource_dir=self.__unpack_data__(self.__IMAGE_RESOURCE_DIRECTORY_format__,data,file_offset=self.get_offset_from_rva(rva))
		if resource_dir is None:self.__warnings.append("Invalid resources directory. Can't parse directory data at RVA: 0x%x"%rva);return
		dir_entries=[];rva+=resource_dir.sizeof();number_of_entries=resource_dir.NumberOfNamedEntries+resource_dir.NumberOfIdEntries;MAX_ALLOWED_ENTRIES=4096
		if number_of_entries>MAX_ALLOWED_ENTRIES:self.__warnings.append('Error parsing the resources directory. The directory contains %d entries (>%s)'%(number_of_entries,MAX_ALLOWED_ENTRIES));return
		self.__total_resource_entries_count+=number_of_entries
		if self.__total_resource_entries_count>MAX_RESOURCE_ENTRIES:self.__warnings.append('Error parsing the resources directory. The file contains at least %d entries (>%d)'%(self.__total_resource_entries_count,MAX_RESOURCE_ENTRIES));return
		strings_to_postprocess=[];last_name_begin_end=None
		for idx in range(number_of_entries):
			if not self.__resource_size_limit_reached and self.__total_resource_bytes>self.__resource_size_limit_upperbounds:self.__resource_size_limit_reached=True;self.__warnings.append('Resource size 0x%x exceeds file size 0x%x, overlapping resources found.'%(self.__total_resource_bytes,self.__resource_size_limit_upperbounds))
			res=self.parse_resource_entry(rva)
			if res is None:self.__warnings.append('Error parsing the resources directory, Entry %d is invalid, RVA = 0x%x. '%(idx,rva));break
			entry_name=None;entry_id=None;name_is_string=(res.Name&2147483648)>>31
			if not name_is_string:entry_id=res.Name
			else:
				ustr_offset=base_rva+res.NameOffset
				try:
					entry_name=UnicodeStringWrapperPostProcessor(self,ustr_offset);self.__total_resource_bytes+=entry_name.get_pascal_16_length()
					if last_name_begin_end and(last_name_begin_end[0]<ustr_offset and last_name_begin_end[1]>=ustr_offset):strings_to_postprocess.pop();self.__warnings.append('Error parsing the resources directory, attempting to read entry name. Entry names overlap 0x%x'%ustr_offset);break
					last_name_begin_end=ustr_offset,ustr_offset+entry_name.get_pascal_16_length();strings_to_postprocess.append(entry_name)
				except PEFormatError:self.__warnings.append("Error parsing the resources directory, attempting to read entry name. Can't read unicode string at offset 0x%x"%ustr_offset)
			if res.DataIsDirectory:
				if base_rva+res.OffsetToDirectory in dirs:break
				entry_directory=self.parse_resources_directory(base_rva+res.OffsetToDirectory,size-(rva-base_rva),base_rva=base_rva,level=level+1,dirs=dirs+[base_rva+res.OffsetToDirectory])
				if not entry_directory:break
				strings=None
				if entry_id==RESOURCE_TYPE['RT_STRING']:
					strings={}
					for resource_id in entry_directory.entries:
						if hasattr(resource_id,'directory'):
							resource_strings={}
							for resource_lang in resource_id.directory.entries:
								if resource_lang is None or not hasattr(resource_lang,'data')or resource_lang.data.struct.Size is None or resource_id.id is None:continue
								string_entry_rva=resource_lang.data.struct.OffsetToData;string_entry_size=resource_lang.data.struct.Size;string_entry_id=resource_id.id
								try:string_entry_data=self.get_data(string_entry_rva,string_entry_size)
								except PEFormatError:self.__warnings.append(f"Error parsing resource of type RT_STRING at RVA 0x{string_entry_rva:x} with size {string_entry_size}");continue
								parse_strings(string_entry_data,(int(string_entry_id)-1)*16,resource_strings);strings.update(resource_strings)
							resource_id.directory.strings=resource_strings
				dir_entries.append(ResourceDirEntryData(struct=res,name=entry_name,id=entry_id,directory=entry_directory))
			else:
				struct=self.parse_resource_data_entry(base_rva+res.OffsetToDirectory)
				if struct:self.__total_resource_bytes+=struct.Size;entry_data=ResourceDataEntryData(struct=struct,lang=res.Name&1023,sublang=res.Name>>10);dir_entries.append(ResourceDirEntryData(struct=res,name=entry_name,id=entry_id,data=entry_data))
				else:break
			if level==0 and res.Id==RESOURCE_TYPE['RT_VERSION']:
				if dir_entries:last_entry=dir_entries[-1]
				try:version_entries=last_entry.directory.entries[0].directory.entries
				except:pass
				else:
					for version_entry in version_entries:
						rt_version_struct=None
						try:rt_version_struct=version_entry.data.struct
						except:pass
						if rt_version_struct is not None:self.parse_version_information(rt_version_struct)
			rva+=res.sizeof()
		string_rvas=[s.get_rva()for s in strings_to_postprocess];string_rvas.sort()
		for(idx,s)in enumerate(strings_to_postprocess):s.render_pascal_16()
		resource_directory_data=ResourceDirData(struct=resource_dir,entries=dir_entries);return resource_directory_data
	def parse_resource_data_entry(self,rva):
		try:data=self.get_data(rva,Structure(self.__IMAGE_RESOURCE_DATA_ENTRY_format__).sizeof())
		except PEFormatError:self.__warnings.append('Error parsing a resource directory data entry, the RVA is invalid: 0x%x'%rva);return
		data_entry=self.__unpack_data__(self.__IMAGE_RESOURCE_DATA_ENTRY_format__,data,file_offset=self.get_offset_from_rva(rva));return data_entry
	def parse_resource_entry(self,rva):
		try:data=self.get_data(rva,Structure(self.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__).sizeof())
		except PEFormatError:return
		resource=self.__unpack_data__(self.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__,data,file_offset=self.get_offset_from_rva(rva))
		if resource is None:return
		resource.NameOffset=resource.Name&2147483647;resource.__pad=resource.Name&4294901760;resource.Id=resource.Name&65535;resource.DataIsDirectory=(resource.OffsetToData&2147483648)>>31;resource.OffsetToDirectory=resource.OffsetToData&2147483647;return resource
	def parse_version_information(self,version_struct):
		try:start_offset=self.get_offset_from_rva(version_struct.OffsetToData)
		except PEFormatError:self.__warnings.append('Error parsing the version information, attempting to read OffsetToData with RVA: 0x{:x}'.format(version_struct.OffsetToData));return
		raw_data=self.__data__[start_offset:start_offset+version_struct.Size];versioninfo_struct=self.__unpack_data__(self.__VS_VERSIONINFO_format__,raw_data,file_offset=start_offset)
		if versioninfo_struct is None:return
		ustr_offset=version_struct.OffsetToData+versioninfo_struct.sizeof();section=self.get_section_by_rva(ustr_offset);section_end=None
		if section:section_end=section.VirtualAddress+max(section.SizeOfRawData,section.Misc_VirtualSize)
		versioninfo_string=None
		try:
			if section_end is None:versioninfo_string=self.get_string_u_at_rva(ustr_offset,encoding='ascii')
			else:versioninfo_string=self.get_string_u_at_rva(ustr_offset,section_end-ustr_offset>>1,encoding='ascii')
		except PEFormatError:self.__warnings.append("Error parsing the version information, attempting to read VS_VERSION_INFO string. Can't read unicode string at offset 0x%x"%ustr_offset)
		if versioninfo_string is None:self.__warnings.append('Invalid VS_VERSION_INFO block: {0}'.format(versioninfo_string));return
		if versioninfo_string is not None and versioninfo_string!=b'VS_VERSION_INFO':
			if len(versioninfo_string)>128:excerpt=versioninfo_string[:128].decode('ascii');excerpt=excerpt[:excerpt.rfind('\\u')];versioninfo_string='{0} ... ({1} bytes, too long to display)'.format(excerpt,len(versioninfo_string)).encode()
			self.__warnings.append('Invalid VS_VERSION_INFO block: {0}'.format(versioninfo_string.decode('ascii').replace('\x00','\\00')));return
		if not hasattr(self,'VS_VERSIONINFO'):self.VS_VERSIONINFO=[]
		vinfo=versioninfo_struct;vinfo.Key=versioninfo_string;self.VS_VERSIONINFO.append(vinfo)
		if versioninfo_string is None:versioninfo_string=''
		fixedfileinfo_offset=self.dword_align(versioninfo_struct.sizeof()+2*(len(versioninfo_string)+1),version_struct.OffsetToData);fixedfileinfo_struct=self.__unpack_data__(self.__VS_FIXEDFILEINFO_format__,raw_data[fixedfileinfo_offset:],file_offset=start_offset+fixedfileinfo_offset)
		if not fixedfileinfo_struct:return
		if not hasattr(self,'VS_FIXEDFILEINFO'):self.VS_FIXEDFILEINFO=[]
		self.VS_FIXEDFILEINFO.append(fixedfileinfo_struct);stringfileinfo_offset=self.dword_align(fixedfileinfo_offset+fixedfileinfo_struct.sizeof(),version_struct.OffsetToData)
		if not hasattr(self,'FileInfo'):self.FileInfo=[]
		finfo=[]
		while True:
			stringfileinfo_struct=self.__unpack_data__(self.__StringFileInfo_format__,raw_data[stringfileinfo_offset:],file_offset=start_offset+stringfileinfo_offset)
			if stringfileinfo_struct is None:self.__warnings.append('Error parsing StringFileInfo/VarFileInfo struct');return
			ustr_offset=version_struct.OffsetToData+stringfileinfo_offset+versioninfo_struct.sizeof()
			try:stringfileinfo_string=self.get_string_u_at_rva(ustr_offset)
			except PEFormatError:self.__warnings.append("Error parsing the version information, attempting to read StringFileInfo string. Can't read unicode string at offset 0x{0:x}".format(ustr_offset));break
			stringfileinfo_struct.Key=stringfileinfo_string;finfo.append(stringfileinfo_struct)
			if stringfileinfo_string and stringfileinfo_string.startswith(b'StringFileInfo'):
				if stringfileinfo_struct.Type in(0,1)and stringfileinfo_struct.ValueLength==0:
					stringtable_offset=self.dword_align(stringfileinfo_offset+stringfileinfo_struct.sizeof()+2*(len(stringfileinfo_string)+1),version_struct.OffsetToData);stringfileinfo_struct.StringTable=[]
					while True:
						stringtable_struct=self.__unpack_data__(self.__StringTable_format__,raw_data[stringtable_offset:],file_offset=start_offset+stringtable_offset)
						if not stringtable_struct:break
						ustr_offset=version_struct.OffsetToData+stringtable_offset+stringtable_struct.sizeof()
						try:stringtable_string=self.get_string_u_at_rva(ustr_offset)
						except PEFormatError:self.__warnings.append("Error parsing the version information, attempting to read StringTable string. Can't read unicode string at offset 0x{0:x}".format(ustr_offset));break
						stringtable_struct.LangID=stringtable_string;stringtable_struct.entries={};stringtable_struct.entries_offsets={};stringtable_struct.entries_lengths={};stringfileinfo_struct.StringTable.append(stringtable_struct);entry_offset=self.dword_align(stringtable_offset+stringtable_struct.sizeof()+2*(len(stringtable_string)+1),version_struct.OffsetToData)
						while entry_offset<stringtable_offset+stringtable_struct.Length:
							string_struct=self.__unpack_data__(self.__String_format__,raw_data[entry_offset:],file_offset=start_offset+entry_offset)
							if not string_struct:break
							ustr_offset=version_struct.OffsetToData+entry_offset+string_struct.sizeof()
							try:key=self.get_string_u_at_rva(ustr_offset);key_offset=self.get_offset_from_rva(ustr_offset)
							except PEFormatError:self.__warnings.append("Error parsing the version information, attempting to read StringTable Key string. Can't read unicode string at offset 0x{0:x}".format(ustr_offset));break
							value_offset=self.dword_align(2*(len(key)+1)+entry_offset+string_struct.sizeof(),version_struct.OffsetToData);ustr_offset=version_struct.OffsetToData+value_offset
							try:value=self.get_string_u_at_rva(ustr_offset,max_length=string_struct.ValueLength);value_offset=self.get_offset_from_rva(ustr_offset)
							except PEFormatError:self.__warnings.append(f"Error parsing the version information, attempting to read StringTable Value string. Can't read unicode string at offset 0x{ustr_offset:x}");break
							if string_struct.Length==0:entry_offset=stringtable_offset+stringtable_struct.Length
							else:entry_offset=self.dword_align(string_struct.Length+entry_offset,version_struct.OffsetToData)
							stringtable_struct.entries[key]=value;stringtable_struct.entries_offsets[key]=key_offset,value_offset;stringtable_struct.entries_lengths[key]=len(key),len(value)
						new_stringtable_offset=self.dword_align(stringtable_struct.Length+stringtable_offset,version_struct.OffsetToData)
						if new_stringtable_offset==stringtable_offset:break
						stringtable_offset=new_stringtable_offset
						if stringtable_offset>=stringfileinfo_struct.Length:break
			elif stringfileinfo_string and stringfileinfo_string.startswith(b'VarFileInfo'):
				varfileinfo_struct=stringfileinfo_struct;varfileinfo_struct.name='VarFileInfo'
				if varfileinfo_struct.Type in(0,1)and varfileinfo_struct.ValueLength==0:
					var_offset=self.dword_align(stringfileinfo_offset+varfileinfo_struct.sizeof()+2*(len(stringfileinfo_string)+1),version_struct.OffsetToData);varfileinfo_struct.Var=[]
					while True:
						var_struct=self.__unpack_data__(self.__Var_format__,raw_data[var_offset:],file_offset=start_offset+var_offset)
						if not var_struct:break
						ustr_offset=version_struct.OffsetToData+var_offset+var_struct.sizeof()
						try:var_string=self.get_string_u_at_rva(ustr_offset)
						except PEFormatError:self.__warnings.append("Error parsing the version information, attempting to read VarFileInfo Var string. Can't read unicode string at offset 0x{0:x}".format(ustr_offset));break
						if var_string is None:break
						varfileinfo_struct.Var.append(var_struct);varword_offset=self.dword_align(2*(len(var_string)+1)+var_offset+var_struct.sizeof(),version_struct.OffsetToData);orig_varword_offset=varword_offset
						while varword_offset<orig_varword_offset+var_struct.ValueLength:
							word1=self.get_word_from_data(raw_data[varword_offset:varword_offset+2],0);word2=self.get_word_from_data(raw_data[varword_offset+2:varword_offset+4],0);varword_offset+=4
							if isinstance(word1,int)and isinstance(word2,int):var_struct.entry={var_string:'0x%04x 0x%04x'%(word1,word2)}
						var_offset=self.dword_align(var_offset+var_struct.Length,version_struct.OffsetToData)
						if var_offset<=var_offset+var_struct.Length:break
			stringfileinfo_offset=self.dword_align(stringfileinfo_struct.Length+stringfileinfo_offset,version_struct.OffsetToData)
			if stringfileinfo_struct.Length==0 or stringfileinfo_offset>=versioninfo_struct.Length:break
		self.FileInfo.append(finfo)
	def parse_export_directory(self,rva,size,forwarded_only=False):
		try:export_dir=self.__unpack_data__(self.__IMAGE_EXPORT_DIRECTORY_format__,self.get_data(rva,Structure(self.__IMAGE_EXPORT_DIRECTORY_format__).sizeof()),file_offset=self.get_offset_from_rva(rva))
		except PEFormatError:self.__warnings.append('Error parsing export directory at RVA: 0x%x'%rva);return
		if not export_dir:return
		def length_until_eof(rva):return len(self.__data__)-self.get_offset_from_rva(rva)
		try:address_of_names=self.get_data(export_dir.AddressOfNames,min(length_until_eof(export_dir.AddressOfNames),export_dir.NumberOfNames*4));address_of_name_ordinals=self.get_data(export_dir.AddressOfNameOrdinals,min(length_until_eof(export_dir.AddressOfNameOrdinals),export_dir.NumberOfNames*4));address_of_functions=self.get_data(export_dir.AddressOfFunctions,min(length_until_eof(export_dir.AddressOfFunctions),export_dir.NumberOfFunctions*4))
		except PEFormatError:self.__warnings.append('Error parsing export directory at RVA: 0x%x'%rva);return
		exports=[];max_failed_entries_before_giving_up=10;section=self.get_section_by_rva(export_dir.AddressOfNames);safety_boundary=len(self.__data__)
		if section:safety_boundary=section.VirtualAddress+len(section.get_data())-export_dir.AddressOfNames
		symbol_counts=collections.defaultdict(int);export_parsing_loop_completed_normally=True
		for i in range(min(export_dir.NumberOfNames,int(safety_boundary/4))):
			symbol_ordinal=self.get_word_from_data(address_of_name_ordinals,i)
			if symbol_ordinal is not None and symbol_ordinal*4<len(address_of_functions):symbol_address=self.get_dword_from_data(address_of_functions,symbol_ordinal)
			else:return
			if symbol_address is None or symbol_address==0:continue
			if symbol_address>=rva and symbol_address<rva+size:
				forwarder_str=self.get_string_at_rva(symbol_address)
				try:forwarder_offset=self.get_offset_from_rva(symbol_address)
				except PEFormatError:continue
			else:
				if forwarded_only:continue
				forwarder_str=None;forwarder_offset=None
			symbol_name_address=self.get_dword_from_data(address_of_names,i)
			if symbol_name_address is None:
				max_failed_entries_before_giving_up-=1
				if max_failed_entries_before_giving_up<=0:export_parsing_loop_completed_normally=False;break
			symbol_name=self.get_string_at_rva(symbol_name_address,MAX_SYMBOL_NAME_LENGTH)
			if not is_valid_function_name(symbol_name,relax_allowed_characters=True):export_parsing_loop_completed_normally=False;break
			try:symbol_name_offset=self.get_offset_from_rva(symbol_name_address)
			except PEFormatError:
				max_failed_entries_before_giving_up-=1
				if max_failed_entries_before_giving_up<=0:export_parsing_loop_completed_normally=False;break
				try:symbol_name_offset=self.get_offset_from_rva(symbol_name_address)
				except PEFormatError:
					max_failed_entries_before_giving_up-=1
					if max_failed_entries_before_giving_up<=0:export_parsing_loop_completed_normally=False;break
					continue
			symbol_counts[symbol_name,symbol_address]+=1
			if symbol_counts[symbol_name,symbol_address]>10:self.__warnings.append(f"Export directory contains more than 10 repeated entries ({symbol_name}, {symbol_address:#02x}). Assuming corrupt.");break
			elif len(symbol_counts)>self.max_symbol_exports:self.__warnings.append('Export directory contains more than {} symbol entries. Assuming corrupt.'.format(self.max_symbol_exports));break
			exports.append(ExportData(pe=self,ordinal=export_dir.Base+symbol_ordinal,ordinal_offset=self.get_offset_from_rva(export_dir.AddressOfNameOrdinals+2*i),address=symbol_address,address_offset=self.get_offset_from_rva(export_dir.AddressOfFunctions+4*symbol_ordinal),name=symbol_name,name_offset=symbol_name_offset,forwarder=forwarder_str,forwarder_offset=forwarder_offset))
		if not export_parsing_loop_completed_normally:self.__warnings.append(f"RVA AddressOfNames in the export directory points to an invalid address: {export_dir.AddressOfNames:x}")
		ordinals={exp.ordinal for exp in exports};max_failed_entries_before_giving_up=10;section=self.get_section_by_rva(export_dir.AddressOfFunctions);safety_boundary=len(self.__data__)
		if section:safety_boundary=section.VirtualAddress+len(section.get_data())-export_dir.AddressOfFunctions
		symbol_counts=collections.defaultdict(int);export_parsing_loop_completed_normally=True
		for idx in range(min(export_dir.NumberOfFunctions,int(safety_boundary/4))):
			if idx+export_dir.Base not in ordinals:
				try:symbol_address=self.get_dword_from_data(address_of_functions,idx)
				except PEFormatError:symbol_address=None
				if symbol_address is None:
					max_failed_entries_before_giving_up-=1
					if max_failed_entries_before_giving_up<=0:export_parsing_loop_completed_normally=False;break
				if symbol_address==0:continue
				if symbol_address is not None and symbol_address>=rva and symbol_address<rva+size:forwarder_str=self.get_string_at_rva(symbol_address)
				else:forwarder_str=None
				symbol_counts[symbol_address]+=1
				if symbol_counts[symbol_address]>self.max_repeated_symbol:self.__warnings.append('Export directory contains more than {} repeated ordinal entries (0x{:x}). Assuming corrupt.'.format(self.max_repeated_symbol,symbol_address));break
				elif len(symbol_counts)>self.max_symbol_exports:self.__warnings.append(f"Export directory contains more than {self.max_symbol_exports} ordinal entries. Assuming corrupt.");break
				exports.append(ExportData(ordinal=export_dir.Base+idx,address=symbol_address,name=None,forwarder=forwarder_str))
		if not export_parsing_loop_completed_normally:self.__warnings.append(f"RVA AddressOfFunctions in the export directory points to an invalid address: {export_dir.AddressOfFunctions:x}");return
		if not exports and export_dir.all_zeroes():return
		return ExportDirData(struct=export_dir,symbols=exports,name=self.get_string_at_rva(export_dir.Name))
	def dword_align(self,offset,base):return(offset+base+3&4294967292)-(base&4294967292)
	def normalize_import_va(self,va):
		begin_of_image=self.OPTIONAL_HEADER.ImageBase;end_of_image=self.OPTIONAL_HEADER.ImageBase+self.OPTIONAL_HEADER.SizeOfImage
		if begin_of_image<=va<end_of_image:va-=begin_of_image
		return va
	def parse_delay_import_directory(self,rva,size):
		import_descs=[];error_count=0
		while True:
			try:data=self.get_data(rva,Structure(self.__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__).sizeof())
			except PEFormatError:self.__warnings.append('Error parsing the Delay import directory at RVA: 0x%x'%rva);break
			file_offset=self.get_offset_from_rva(rva);import_desc=self.__unpack_data__(self.__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__,data,file_offset=file_offset)
			if not import_desc or import_desc.all_zeroes():break
			contains_addresses=False
			if import_desc.grAttrs==0 and self.FILE_HEADER.Machine==MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:import_desc.pBoundIAT=self.normalize_import_va(import_desc.pBoundIAT);import_desc.pIAT=self.normalize_import_va(import_desc.pIAT);import_desc.pINT=self.normalize_import_va(import_desc.pINT);import_desc.pUnloadIAT=self.normalize_import_va(import_desc.pUnloadIAT);import_desc.phmod=self.normalize_import_va(import_desc.pUnloadIAT);import_desc.szName=self.normalize_import_va(import_desc.szName);contains_addresses=True
			rva+=import_desc.sizeof();max_len=len(self.__data__)-file_offset
			if rva>import_desc.pINT or rva>import_desc.pIAT:max_len=max(rva-import_desc.pINT,rva-import_desc.pIAT)
			import_data=[]
			try:import_data=self.parse_imports(import_desc.pINT,import_desc.pIAT,None,max_len,contains_addresses)
			except PEFormatError as excp:self.__warnings.append('Error parsing the Delay import directory. Invalid import data at RVA: 0x{0:x} ({1})'.format(rva,excp.value))
			if error_count>5:self.__warnings.append('Too many errors parsing the Delay import directory. Invalid import data at RVA: 0x{0:x}'.format(rva));break
			if not import_data:error_count+=1;continue
			if self.__total_import_symbols>MAX_IMPORT_SYMBOLS:self.__warnings.append('Error, too many imported symbols %d (>%s)'%(self.__total_import_symbols,MAX_IMPORT_SYMBOLS));break
			dll=self.get_string_at_rva(import_desc.szName,MAX_DLL_LENGTH)
			if not is_valid_dos_filename(dll):dll=b'*invalid*'
			if dll:
				for symbol in import_data:
					if symbol.name is None:
						funcname=ordlookup.ordLookup(dll.lower(),symbol.ordinal)
						if funcname:symbol.name=funcname
				import_descs.append(ImportDescData(struct=import_desc,imports=import_data,dll=dll))
		return import_descs
	def get_rich_header_hash(self,algorithm='md5'):
		if not hasattr(self,'RICH_HEADER')or self.RICH_HEADER is None:return''
		if algorithm=='md5':return md5(self.RICH_HEADER.clear_data).hexdigest()
		elif algorithm=='sha1':return sha1(self.RICH_HEADER.clear_data).hexdigest()
		elif algorithm=='sha256':return sha256(self.RICH_HEADER.clear_data).hexdigest()
		elif algorithm=='sha512':return sha512(self.RICH_HEADER.clear_data).hexdigest()
		raise Exception('Invalid hashing algorithm specified')
	def get_imphash(self):
		impstrs=[];exts=['ocx','sys','dll']
		if not hasattr(self,'DIRECTORY_ENTRY_IMPORT'):return''
		for entry in self.DIRECTORY_ENTRY_IMPORT:
			if isinstance(entry.dll,bytes):libname=entry.dll.decode().lower()
			else:libname=entry.dll.lower()
			parts=libname.rsplit('.',1)
			if len(parts)>1 and parts[1]in exts:libname=parts[0]
			entry_dll_lower=entry.dll.lower()
			for imp in entry.imports:
				funcname=None
				if not imp.name:
					funcname=ordlookup.ordLookup(entry_dll_lower,imp.ordinal,make_name=True)
					if not funcname:raise PEFormatError(f"Unable to look up ordinal {entry.dll}:{imp.ordinal:04x}")
				else:funcname=imp.name
				if not funcname:continue
				if isinstance(funcname,bytes):funcname=funcname.decode()
				impstrs.append('%s.%s'%(libname.lower(),funcname.lower()))
		return md5(','.join(impstrs).encode()).hexdigest()
	def get_exphash(self):
		if not hasattr(self,'DIRECTORY_ENTRY_EXPORT'):return''
		if not hasattr(self.DIRECTORY_ENTRY_EXPORT,'symbols'):return''
		export_list=[e.name.decode().lower()for e in self.DIRECTORY_ENTRY_EXPORT.symbols if e and e.name is not None]
		if len(export_list)==0:return''
		return md5(','.join(export_list).encode()).hexdigest()
	def parse_import_directory(self,rva,size,dllnames_only=False):
		import_descs=[];error_count=0;image_import_descriptor_size=Structure(self.__IMAGE_IMPORT_DESCRIPTOR_format__).sizeof()
		while True:
			try:data=self.get_data(rva,image_import_descriptor_size)
			except PEFormatError:self.__warnings.append(f"Error parsing the import directory at RVA: 0x{rva:x}");break
			file_offset=self.get_offset_from_rva(rva);import_desc=self.__unpack_data__(self.__IMAGE_IMPORT_DESCRIPTOR_format__,data,file_offset=file_offset)
			if not import_desc or import_desc.all_zeroes():break
			rva+=import_desc.sizeof();max_len=len(self.__data__)-file_offset
			if rva>import_desc.OriginalFirstThunk or rva>import_desc.FirstThunk:max_len=max(rva-import_desc.OriginalFirstThunk,rva-import_desc.FirstThunk)
			import_data=[]
			if not dllnames_only:
				try:import_data=self.parse_imports(import_desc.OriginalFirstThunk,import_desc.FirstThunk,import_desc.ForwarderChain,max_length=max_len)
				except PEFormatError as e:self.__warnings.append(f"Error parsing the import directory. Invalid Import data at RVA: 0x{rva:x} ({e.value})")
				if error_count>5:self.__warnings.append(f"Too many errors parsing the import directory. Invalid import data at RVA: 0x{rva:x}");break
				if not import_data:error_count+=1;continue
			dll=self.get_string_at_rva(import_desc.Name,MAX_DLL_LENGTH)
			if not is_valid_dos_filename(dll):dll=b'*invalid*'
			if dll:
				for symbol in import_data:
					if symbol.name is None:
						funcname=ordlookup.ordLookup(dll.lower(),symbol.ordinal)
						if funcname:symbol.name=funcname
				import_descs.append(ImportDescData(struct=import_desc,imports=import_data,dll=dll))
		if not dllnames_only:
			suspicious_imports={'LoadLibrary','GetProcAddress'};suspicious_imports_count=0;total_symbols=0
			for imp_dll in import_descs:
				for symbol in imp_dll.imports:
					for suspicious_symbol in suspicious_imports:
						if not symbol or not symbol.name:continue
						name=symbol.name
						if type(symbol.name)==bytes:name=symbol.name.decode('utf-8')
						if name.startswith(suspicious_symbol):suspicious_imports_count+=1;break
					total_symbols+=1
			if suspicious_imports_count==len(suspicious_imports)and total_symbols<20:self.__warnings.append('Imported symbols contain entries typical of packed executables.')
		return import_descs
	def parse_imports(self,original_first_thunk,first_thunk,forwarder_chain,max_length=None,contains_addresses=False):
		imported_symbols=[];ilt=self.get_import_table(original_first_thunk,max_length,contains_addresses);iat=self.get_import_table(first_thunk,max_length,contains_addresses)
		if(not iat or len(iat)==0)and(not ilt or len(ilt)==0):self.__warnings.append(f"Damaged Import Table information. ILT and/or IAT appear to be broken. OriginalFirstThunk: 0x{original_first_thunk:x} FirstThunk: 0x{first_thunk:x}");return[]
		table=None
		if ilt:table=ilt
		elif iat:table=iat
		else:return
		imp_offset=4;address_mask=2147483647
		if self.PE_TYPE==OPTIONAL_HEADER_MAGIC_PE:ordinal_flag=IMAGE_ORDINAL_FLAG
		elif self.PE_TYPE==OPTIONAL_HEADER_MAGIC_PE_PLUS:ordinal_flag=IMAGE_ORDINAL_FLAG64;imp_offset=8;address_mask=0x7fffffffffffffff
		else:ordinal_flag=IMAGE_ORDINAL_FLAG
		num_invalid=0
		for(idx,tbl_entry)in enumerate(table):
			imp_ord=None;imp_hint=None;imp_name=None;name_offset=None;hint_name_table_rva=None;import_by_ordinal=False
			if tbl_entry.AddressOfData:
				if tbl_entry.AddressOfData&ordinal_flag:import_by_ordinal=True;imp_ord=tbl_entry.AddressOfData&65535;imp_name=None;name_offset=None
				else:
					import_by_ordinal=False
					try:
						hint_name_table_rva=tbl_entry.AddressOfData&address_mask;data=self.get_data(hint_name_table_rva,2);imp_hint=self.get_word_from_data(data,0);imp_name=self.get_string_at_rva(tbl_entry.AddressOfData+2,MAX_IMPORT_NAME_LENGTH)
						if not is_valid_function_name(imp_name):imp_name=b'*invalid*'
						name_offset=self.get_offset_from_rva(tbl_entry.AddressOfData+2)
					except PEFormatError:pass
				thunk_offset=tbl_entry.get_file_offset();thunk_rva=self.get_rva_from_offset(thunk_offset)
			imp_address=first_thunk+self.OPTIONAL_HEADER.ImageBase+idx*imp_offset;struct_iat=None
			try:
				if iat and ilt and ilt[idx].AddressOfData!=iat[idx].AddressOfData:imp_bound=iat[idx].AddressOfData;struct_iat=iat[idx]
				else:imp_bound=None
			except IndexError:imp_bound=None
			if imp_ord is None and imp_name is None:raise PEFormatError('Invalid entries, aborting parsing.')
			if imp_name==b'*invalid*':
				if num_invalid>1000 and num_invalid==idx:raise PEFormatError('Too many invalid names, aborting parsing.')
				num_invalid+=1;continue
			if imp_ord or imp_name:imported_symbols.append(ImportData(pe=self,struct_table=tbl_entry,struct_iat=struct_iat,import_by_ordinal=import_by_ordinal,ordinal=imp_ord,ordinal_offset=tbl_entry.get_file_offset(),hint=imp_hint,name=imp_name,name_offset=name_offset,bound=imp_bound,address=imp_address,hint_name_table_rva=hint_name_table_rva,thunk_offset=thunk_offset,thunk_rva=thunk_rva))
		return imported_symbols
	def get_import_table(self,rva,max_length=None,contains_addresses=False):
		table=[]
		if self.PE_TYPE==OPTIONAL_HEADER_MAGIC_PE:ordinal_flag=IMAGE_ORDINAL_FLAG;format=self.__IMAGE_THUNK_DATA_format__
		elif self.PE_TYPE==OPTIONAL_HEADER_MAGIC_PE_PLUS:ordinal_flag=IMAGE_ORDINAL_FLAG64;format=self.__IMAGE_THUNK_DATA64_format__
		else:ordinal_flag=IMAGE_ORDINAL_FLAG;format=self.__IMAGE_THUNK_DATA_format__
		expected_size=Structure(format).sizeof();MAX_ADDRESS_SPREAD=128*2**20;ADDR_4GB=2**32;MAX_REPEATED_ADDRESSES=15;repeated_address=0;addresses_of_data_set_64=AddressSet();addresses_of_data_set_32=AddressSet();start_rva=rva
		while rva:
			if max_length is not None and rva>=start_rva+max_length:self.__warnings.append('Error parsing the import table. Entries go beyond bounds.');break
			if self.__total_import_symbols>MAX_IMPORT_SYMBOLS:self.__warnings.append('Excessive number of imports %d (>%s)'%(self.__total_import_symbols,MAX_IMPORT_SYMBOLS));break
			self.__total_import_symbols+=1
			if repeated_address>=MAX_REPEATED_ADDRESSES:return[]
			if addresses_of_data_set_32.diff()>MAX_ADDRESS_SPREAD:return[]
			if addresses_of_data_set_64.diff()>MAX_ADDRESS_SPREAD:return[]
			failed=False
			try:data=self.get_data(rva,expected_size)
			except PEFormatError:failed=True
			if failed or len(data)!=expected_size:self.__warnings.append('Error parsing the import table. Invalid data at RVA: 0x%x'%rva);return
			thunk_data=self.__unpack_data__(format,data,file_offset=self.get_offset_from_rva(rva))
			if contains_addresses:thunk_data.AddressOfData=self.normalize_import_va(thunk_data.AddressOfData);thunk_data.ForwarderString=self.normalize_import_va(thunk_data.ForwarderString);thunk_data.Function=self.normalize_import_va(thunk_data.Function);thunk_data.Ordinal=self.normalize_import_va(thunk_data.Ordinal)
			if thunk_data and thunk_data.AddressOfData>=start_rva and thunk_data.AddressOfData<=rva:self.__warnings.append('Error parsing the import table. AddressOfData overlaps with THUNK_DATA for THUNK at RVA 0x%x'%rva);break
			if thunk_data and thunk_data.AddressOfData:
				addr_of_data=thunk_data.AddressOfData
				if addr_of_data&ordinal_flag:
					if addr_of_data&2147483647>65535:return[]
				else:
					if addr_of_data>=ADDR_4GB:the_set=addresses_of_data_set_64
					else:the_set=addresses_of_data_set_32
					if addr_of_data in the_set:repeated_address+=1
					the_set.add(addr_of_data)
			if not thunk_data or thunk_data.all_zeroes():break
			rva+=thunk_data.sizeof();table.append(thunk_data)
		return table
	def get_memory_mapped_image(self,max_virtual_address=268435456,ImageBase=None):
		if ImageBase is not None:original_data=self.__data__;self.relocate_image(ImageBase)
		mapped_data=self.header
		for section in self.sections:
			if section.Misc_VirtualSize==0 and section.SizeOfRawData==0:continue
			srd=section.SizeOfRawData;prd=self.adjust_PointerToRawData(section.PointerToRawData);VirtualAddress_adj=self.adjust_SectionAlignment(section.VirtualAddress,self.OPTIONAL_HEADER.SectionAlignment,self.OPTIONAL_HEADER.FileAlignment)
			if srd>len(self.__data__)or prd>len(self.__data__)or srd+prd>len(self.__data__)or VirtualAddress_adj>=max_virtual_address:continue
			padding_length=VirtualAddress_adj-len(mapped_data)
			if padding_length>0:mapped_data+=b'\x00'*padding_length
			elif padding_length<0:mapped_data=mapped_data[:padding_length]
			mapped_data+=section.get_data()
		if ImageBase is not None:self.__data__=original_data
		return mapped_data
	def get_resources_strings(self):
		resources_strings=[]
		if hasattr(self,'DIRECTORY_ENTRY_RESOURCE'):
			for res_type in self.DIRECTORY_ENTRY_RESOURCE.entries:
				if hasattr(res_type,'directory'):
					for resource_id in res_type.directory.entries:
						if hasattr(resource_id,'directory'):
							if hasattr(resource_id.directory,'strings')and resource_id.directory.strings:
								for res_string in list(resource_id.directory.strings.values()):resources_strings.append(res_string)
		return resources_strings
	def get_data(self,rva=0,length=None):
		s=self.get_section_by_rva(rva)
		if length is None:end=None
		else:end=rva+length
		if not s:
			if rva<len(self.header):return self.header[rva:end]
			if rva<len(self.__data__):return self.__data__[rva:end]
			raise PEFormatError("data at RVA can't be fetched. Corrupt header?")
		return s.get_data(rva,length)
	def get_rva_from_offset(self,offset):
		s=self.get_section_by_offset(offset)
		if not s:
			if self.sections:
				lowest_rva=min([self.adjust_SectionAlignment(s.VirtualAddress,self.OPTIONAL_HEADER.SectionAlignment,self.OPTIONAL_HEADER.FileAlignment)for s in self.sections])
				if offset<lowest_rva:return offset
				return
			else:return offset
		return s.get_rva_from_offset(offset)
	def get_offset_from_rva(self,rva):
		s=self.get_section_by_rva(rva)
		if not s:
			if rva<len(self.__data__):return rva
			raise PEFormatError(f"data at RVA 0x{rva:x} can't be fetched")
		return s.get_offset_from_rva(rva)
	def get_string_at_rva(self,rva,max_length=MAX_STRING_LENGTH):
		if rva is None:return
		s=self.get_section_by_rva(rva)
		if not s:return self.get_string_from_data(0,self.__data__[rva:rva+max_length])
		return self.get_string_from_data(0,s.get_data(rva,length=max_length))
	def get_bytes_from_data(self,offset,data):
		if offset>len(data):return b''
		d=data[offset:]
		if isinstance(d,bytearray):return bytes(d)
		return d
	def get_string_from_data(self,offset,data):
		s=self.get_bytes_from_data(offset,data);end=s.find(b'\x00')
		if end>=0:s=s[:end]
		return s
	def get_string_u_at_rva(self,rva,max_length=2**16,encoding=None):
		if max_length==0:return b''
		data=self.get_data(rva,2);max_length<<=1;requested=min(max_length,256);data=self.get_data(rva,requested);null_index=-1
		while True:
			null_index=data.find(b'\x00\x00',null_index+1)
			if null_index==-1:
				data_length=len(data)
				if data_length<requested or data_length==max_length:null_index=len(data)>>1;break
				data+=self.get_data(rva+data_length,max_length-data_length);null_index=requested-1;requested=max_length
			elif null_index%2==0:null_index>>=1;break
		uchrs=struct.unpack('<{:d}H'.format(null_index),data[:null_index*2]);s=''.join(map(chr,uchrs))
		if encoding:return s.encode(encoding,'backslashreplace_')
		return s.encode('utf-8','backslashreplace_')
	def get_section_by_offset(self,offset):
		for section in self.sections:
			if section.contains_offset(offset):return section
	def get_section_by_rva(self,rva):
		if self._get_section_by_rva_last_used is not None:
			if self._get_section_by_rva_last_used.contains_rva(rva):return self._get_section_by_rva_last_used
		for section in self.sections:
			if section.contains_rva(rva):self._get_section_by_rva_last_used=section;return section
	def __str__(self):return self.dump_info()
	def has_relocs(self):return hasattr(self,'DIRECTORY_ENTRY_BASERELOC')
	def has_dynamic_relocs(self):
		if hasattr(self,'DIRECTORY_ENTRY_LOAD_CONFIG'):
			if self.DIRECTORY_ENTRY_LOAD_CONFIG.dynamic_relocations:return True
		return False
	def print_info(self,encoding='utf-8'):print(self.dump_info(encoding=encoding))
	def dump_info(self,dump=None,encoding='ascii'):
		if dump is None:dump=Dump()
		warnings=self.get_warnings()
		if warnings:
			dump.add_header('Parsing Warnings')
			for warning in warnings:dump.add_line(warning);dump.add_newline()
		dump.add_header('DOS_HEADER');dump.add_lines(self.DOS_HEADER.dump());dump.add_newline();dump.add_header('NT_HEADERS');dump.add_lines(self.NT_HEADERS.dump());dump.add_newline();dump.add_header('FILE_HEADER');dump.add_lines(self.FILE_HEADER.dump());image_flags=retrieve_flags(IMAGE_CHARACTERISTICS,'IMAGE_FILE_');dump.add('Flags: ');flags=[]
		for flag in sorted(image_flags):
			if getattr(self.FILE_HEADER,flag[0]):flags.append(flag[0])
		dump.add_line(', '.join(flags));dump.add_newline()
		if hasattr(self,'OPTIONAL_HEADER')and self.OPTIONAL_HEADER is not None:dump.add_header('OPTIONAL_HEADER');dump.add_lines(self.OPTIONAL_HEADER.dump())
		dll_characteristics_flags=retrieve_flags(DLL_CHARACTERISTICS,'IMAGE_DLLCHARACTERISTICS_');dump.add('DllCharacteristics: ');flags=[]
		for flag in sorted(dll_characteristics_flags):
			if getattr(self.OPTIONAL_HEADER,flag[0]):flags.append(flag[0])
		dump.add_line(', '.join(flags));ex_dll_characteristics_flags=retrieve_flags(EX_DLL_CHARACTERISTICS,'IMAGE_DLLCHARACTERISTICS_EX_')
		if ex_dll_characteristics_flags:
			flags=[]
			if hasattr(self,'DIRECTORY_ENTRY_DEBUG')and self.DIRECTORY_ENTRY_DEBUG is not None:
				for debug_entry in self.DIRECTORY_ENTRY_DEBUG:
					if debug_entry.struct.Type==DEBUG_TYPE['IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS']:
						for flag in sorted(ex_dll_characteristics_flags):
							if getattr(debug_entry.entry,flag[0]):flags.append(flag[0])
			if flags:dump.add('ExDllCharacteristics: ');dump.add_line(', '.join(flags))
		dump.add_newline();dump.add_header('PE Sections');section_flags=retrieve_flags(SECTION_CHARACTERISTICS,'IMAGE_SCN_')
		for section in self.sections:
			dump.add_lines(section.dump());dump.add('Flags: ');flags=[]
			for flag in sorted(section_flags):
				if getattr(section,flag[0]):flags.append(flag[0])
			dump.add_line(', '.join(flags));dump.add_line('Entropy: {0:f} (Min=0.0, Max=8.0)'.format(section.get_entropy()))
			if md5 is not None:dump.add_line('MD5     hash: {0}'.format(section.get_hash_md5()))
			if sha1 is not None:dump.add_line('SHA-1   hash: %s'%section.get_hash_sha1())
			if sha256 is not None:dump.add_line('SHA-256 hash: %s'%section.get_hash_sha256())
			if sha512 is not None:dump.add_line('SHA-512 hash: %s'%section.get_hash_sha512())
			dump.add_newline()
		if hasattr(self,'OPTIONAL_HEADER')and hasattr(self.OPTIONAL_HEADER,'DATA_DIRECTORY'):
			dump.add_header('Directories')
			for directory in self.OPTIONAL_HEADER.DATA_DIRECTORY:
				if directory is not None:dump.add_lines(directory.dump())
			dump.add_newline()
		if hasattr(self,'VS_VERSIONINFO'):
			for(idx,vinfo_entry)in enumerate(self.VS_VERSIONINFO):
				if len(self.VS_VERSIONINFO)>1:dump.add_header(f"Version Information {idx+1}")
				else:dump.add_header('Version Information')
				if vinfo_entry is not None:dump.add_lines(vinfo_entry.dump())
				dump.add_newline()
				if hasattr(self,'VS_FIXEDFILEINFO'):dump.add_lines(self.VS_FIXEDFILEINFO[idx].dump());dump.add_newline()
				if hasattr(self,'FileInfo')and len(self.FileInfo)>idx:
					for entry in self.FileInfo[idx]:
						dump.add_lines(entry.dump());dump.add_newline()
						if hasattr(entry,'StringTable'):
							for st_entry in entry.StringTable:
								[dump.add_line('  '+line)for line in st_entry.dump()];dump.add_line('  LangID: {0}'.format(st_entry.LangID.decode(encoding,'backslashreplace_')));dump.add_newline()
								for str_entry in sorted(list(st_entry.entries.items())):dump.add_line('    {0}: {1}'.format(str_entry[0].decode(encoding,'backslashreplace_'),str_entry[1].decode(encoding,'backslashreplace_')))
							dump.add_newline()
						elif hasattr(entry,'Var'):
							for var_entry in entry.Var:
								if hasattr(var_entry,'entry'):[dump.add_line('  '+line)for line in var_entry.dump()];dump.add_line('    {0}: {1}'.format(list(var_entry.entry.keys())[0].decode('utf-8','backslashreplace_'),list(var_entry.entry.values())[0]))
							dump.add_newline()
		if hasattr(self,'DIRECTORY_ENTRY_EXPORT'):
			dump.add_header('Exported symbols');dump.add_lines(self.DIRECTORY_ENTRY_EXPORT.struct.dump());dump.add_newline();dump.add_line('%-10s   %-10s  %s'%('Ordinal','RVA','Name'))
			for export in self.DIRECTORY_ENTRY_EXPORT.symbols:
				if export.address is not None:
					name=b'None'
					if export.name:name=export.name
					dump.add('%-10d 0x%08X    %s'%(export.ordinal,export.address,name.decode(encoding)))
					if export.forwarder:dump.add_line(' forwarder: {0}'.format(export.forwarder.decode(encoding,'backslashreplace_')))
					else:dump.add_newline()
			dump.add_newline()
		if hasattr(self,'DIRECTORY_ENTRY_IMPORT'):
			dump.add_header('Imported symbols')
			for module in self.DIRECTORY_ENTRY_IMPORT:
				dump.add_lines(module.struct.dump())
				if not module.imports:dump.add('  Name -> {0}'.format(self.get_string_at_rva(module.struct.Name).decode(encoding,'backslashreplace_')));dump.add_newline()
				dump.add_newline()
				for symbol in module.imports:
					if symbol.bound:dump.add_line(' Bound: 0x{0:08X}'.format(symbol.bound))
					else:dump.add_newline()
				dump.add_newline()
		if hasattr(self,'DIRECTORY_ENTRY_BOUND_IMPORT'):
			dump.add_header('Bound imports')
			for bound_imp_desc in self.DIRECTORY_ENTRY_BOUND_IMPORT:
				dump.add_lines(bound_imp_desc.struct.dump());dump.add_line('DLL: {0}'.format(bound_imp_desc.name.decode(encoding,'backslashreplace_')));dump.add_newline()
				for bound_imp_ref in bound_imp_desc.entries:dump.add_lines(bound_imp_ref.struct.dump(),4);dump.add_line('DLL: {0}'.format(bound_imp_ref.name.decode(encoding,'backslashreplace_')),4);dump.add_newline()
		if hasattr(self,'DIRECTORY_ENTRY_DELAY_IMPORT'):
			dump.add_header('Delay Imported symbols')
			for module in self.DIRECTORY_ENTRY_DELAY_IMPORT:
				dump.add_lines(module.struct.dump());dump.add_newline()
				for symbol in module.imports:
					if symbol.bound:dump.add_line(' Bound: 0x{0:08X}'.format(symbol.bound))
					else:dump.add_newline()
				dump.add_newline()
		if hasattr(self,'DIRECTORY_ENTRY_RESOURCE'):
			dump.add_header('Resource directory');dump.add_lines(self.DIRECTORY_ENTRY_RESOURCE.struct.dump())
			for res_type in self.DIRECTORY_ENTRY_RESOURCE.entries:
				if res_type.name is not None:name=res_type.name.decode(encoding,'backslashreplace_');dump.add_line(f"Name: [{name}]",2)
				else:res_type_id=RESOURCE_TYPE.get(res_type.struct.Id,'-');dump.add_line(f"Id: [0x{res_type.struct.Id:X}] ({res_type_id})",2)
				dump.add_lines(res_type.struct.dump(),2)
				if hasattr(res_type,'directory'):
					dump.add_lines(res_type.directory.struct.dump(),4)
					for resource_id in res_type.directory.entries:
						if resource_id.name is not None:name=resource_id.name.decode('utf-8','backslashreplace_');dump.add_line(f"Name: [{name}]",6)
						else:dump.add_line(f"Id: [0x{resource_id.struct.Id:X}]",6)
						dump.add_lines(resource_id.struct.dump(),6)
						if hasattr(resource_id,'directory'):
							dump.add_lines(resource_id.directory.struct.dump(),8)
							for resource_lang in resource_id.directory.entries:
								if hasattr(resource_lang,'data'):dump.add_line('\\--- LANG [%d,%d][%s,%s]'%(resource_lang.data.lang,resource_lang.data.sublang,LANG.get(resource_lang.data.lang,'*unknown*'),get_sublang_name_for_lang(resource_lang.data.lang,resource_lang.data.sublang)),8);dump.add_lines(resource_lang.struct.dump(),10);dump.add_lines(resource_lang.data.struct.dump(),12)
							if hasattr(resource_id.directory,'strings')and resource_id.directory.strings:
								dump.add_line('[STRINGS]',10)
								for(idx,res_string)in list(sorted(resource_id.directory.strings.items())):dump.add_line('{0:6d}: {1}'.format(idx,res_string.encode('unicode-escape','backslashreplace').decode('ascii')),12)
				dump.add_newline()
			dump.add_newline()
		if hasattr(self,'DIRECTORY_ENTRY_TLS')and self.DIRECTORY_ENTRY_TLS and self.DIRECTORY_ENTRY_TLS.struct:dump.add_header('TLS');dump.add_lines(self.DIRECTORY_ENTRY_TLS.struct.dump());dump.add_newline()
		if hasattr(self,'DIRECTORY_ENTRY_LOAD_CONFIG')and self.DIRECTORY_ENTRY_LOAD_CONFIG and self.DIRECTORY_ENTRY_LOAD_CONFIG.struct:dump.add_header('LOAD_CONFIG');dump.add_lines(self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.dump());dump.add_newline()
		if hasattr(self,'DIRECTORY_ENTRY_DEBUG'):
			dump.add_header('Debug information')
			for dbg in self.DIRECTORY_ENTRY_DEBUG:
				dump.add_lines(dbg.struct.dump())
				try:dump.add_line('Type: '+DEBUG_TYPE[dbg.struct.Type])
				except KeyError:dump.add_line('Type: 0x{0:x}(Unknown)'.format(dbg.struct.Type))
				dump.add_newline()
				if dbg.entry:dump.add_lines(dbg.entry.dump(),4);dump.add_newline()
		if self.has_relocs():
			dump.add_header('Base relocations')
			for base_reloc in self.DIRECTORY_ENTRY_BASERELOC:
				dump.add_lines(base_reloc.struct.dump())
				for reloc in base_reloc.entries:
					try:dump.add_line('%08Xh %s'%(reloc.rva,RELOCATION_TYPE[reloc.type][16:]),4)
					except KeyError:dump.add_line('0x%08X 0x%x(Unknown)'%(reloc.rva,reloc.type),4)
				dump.add_newline()
		if hasattr(self,'DIRECTORY_ENTRY_EXCEPTION')and len(self.DIRECTORY_ENTRY_EXCEPTION)>0:
			dump.add_header('Unwind data for exception handling')
			for rf in self.DIRECTORY_ENTRY_EXCEPTION:
				dump.add_lines(rf.struct.dump())
				if hasattr(rf,'unwindinfo')and rf.unwindinfo is not None:dump.add_lines(rf.unwindinfo.dump(),4)
		return dump.get_text()
	def dump_dict(self):
		dump_dict={};warnings=self.get_warnings()
		if warnings:dump_dict['Parsing Warnings']=warnings
		dump_dict['DOS_HEADER']=self.DOS_HEADER.dump_dict();dump_dict['NT_HEADERS']=self.NT_HEADERS.dump_dict();dump_dict['FILE_HEADER']=self.FILE_HEADER.dump_dict();image_flags=retrieve_flags(IMAGE_CHARACTERISTICS,'IMAGE_FILE_');dump_dict['Flags']=[]
		for flag in image_flags:
			if getattr(self.FILE_HEADER,flag[0]):dump_dict['Flags'].append(flag[0])
		if hasattr(self,'OPTIONAL_HEADER')and self.OPTIONAL_HEADER is not None:dump_dict['OPTIONAL_HEADER']=self.OPTIONAL_HEADER.dump_dict()
		dll_characteristics_flags=retrieve_flags(DLL_CHARACTERISTICS,'IMAGE_DLLCHARACTERISTICS_');dump_dict['DllCharacteristics']=[]
		for flag in dll_characteristics_flags:
			if getattr(self.OPTIONAL_HEADER,flag[0]):dump_dict['DllCharacteristics'].append(flag[0])
		dump_dict['PE Sections']=[];section_flags=retrieve_flags(SECTION_CHARACTERISTICS,'IMAGE_SCN_')
		for section in self.sections:
			section_dict=section.dump_dict();dump_dict['PE Sections'].append(section_dict);section_dict['Flags']=[]
			for flag in section_flags:
				if getattr(section,flag[0]):section_dict['Flags'].append(flag[0])
			section_dict['Entropy']=section.get_entropy()
			if md5 is not None:section_dict['MD5']=section.get_hash_md5()
			if sha1 is not None:section_dict['SHA1']=section.get_hash_sha1()
			if sha256 is not None:section_dict['SHA256']=section.get_hash_sha256()
			if sha512 is not None:section_dict['SHA512']=section.get_hash_sha512()
		if hasattr(self,'OPTIONAL_HEADER')and hasattr(self.OPTIONAL_HEADER,'DATA_DIRECTORY'):
			dump_dict['Directories']=[]
			for(idx,directory)in enumerate(self.OPTIONAL_HEADER.DATA_DIRECTORY):
				if directory is not None:dump_dict['Directories'].append(directory.dump_dict())
		if hasattr(self,'VS_VERSIONINFO'):
			dump_dict['Version Information']=[]
			for(idx,vs_vinfo)in enumerate(self.VS_VERSIONINFO):
				version_info_list=[];version_info_list.append(vs_vinfo.dump_dict())
				if hasattr(self,'VS_FIXEDFILEINFO'):version_info_list.append(self.VS_FIXEDFILEINFO[idx].dump_dict())
				if hasattr(self,'FileInfo')and len(self.FileInfo)>idx:
					fileinfo_list=[];version_info_list.append(fileinfo_list)
					for entry in self.FileInfo[idx]:
						fileinfo_list.append(entry.dump_dict())
						if hasattr(entry,'StringTable'):
							stringtable_dict={}
							for st_entry in entry.StringTable:
								fileinfo_list.extend(st_entry.dump_dict());stringtable_dict['LangID']=st_entry.LangID
								for str_entry in list(st_entry.entries.items()):stringtable_dict[str_entry[0]]=str_entry[1]
							fileinfo_list.append(stringtable_dict)
						elif hasattr(entry,'Var'):
							for var_entry in entry.Var:
								var_dict={}
								if hasattr(var_entry,'entry'):fileinfo_list.extend(var_entry.dump_dict());var_dict[list(var_entry.entry.keys())[0]]=list(var_entry.entry.values())[0];fileinfo_list.append(var_dict)
				dump_dict['Version Information'].append(version_info_list)
		if hasattr(self,'DIRECTORY_ENTRY_EXPORT'):
			dump_dict['Exported symbols']=[];dump_dict['Exported symbols'].append(self.DIRECTORY_ENTRY_EXPORT.struct.dump_dict())
			for export in self.DIRECTORY_ENTRY_EXPORT.symbols:
				export_dict={}
				if export.address is not None:
					export_dict.update({'Ordinal':export.ordinal,'RVA':export.address,'Name':export.name})
					if export.forwarder:export_dict['forwarder']=export.forwarder
				dump_dict['Exported symbols'].append(export_dict)
		if hasattr(self,'DIRECTORY_ENTRY_IMPORT'):
			dump_dict['Imported symbols']=[]
			for module in self.DIRECTORY_ENTRY_IMPORT:
				import_list=[];dump_dict['Imported symbols'].append(import_list);import_list.append(module.struct.dump_dict())
				for symbol in module.imports:
					symbol_dict={}
					if symbol.bound:symbol_dict['Bound']=symbol.bound
					import_list.append(symbol_dict)
		if hasattr(self,'DIRECTORY_ENTRY_BOUND_IMPORT'):
			dump_dict['Bound imports']=[]
			for bound_imp_desc in self.DIRECTORY_ENTRY_BOUND_IMPORT:
				bound_imp_desc_dict={};dump_dict['Bound imports'].append(bound_imp_desc_dict);bound_imp_desc_dict.update(bound_imp_desc.struct.dump_dict());bound_imp_desc_dict['DLL']=bound_imp_desc.name
				for bound_imp_ref in bound_imp_desc.entries:bound_imp_ref_dict={};bound_imp_ref_dict.update(bound_imp_ref.struct.dump_dict());bound_imp_ref_dict['DLL']=bound_imp_ref.name
		if hasattr(self,'DIRECTORY_ENTRY_DELAY_IMPORT'):
			dump_dict['Delay Imported symbols']=[]
			for module in self.DIRECTORY_ENTRY_DELAY_IMPORT:
				module_list=[];dump_dict['Delay Imported symbols'].append(module_list);module_list.append(module.struct.dump_dict())
				for symbol in module.imports:
					symbol_dict={}
					if symbol.bound:symbol_dict['Bound']=symbol.bound
					module_list.append(symbol_dict)
		if hasattr(self,'DIRECTORY_ENTRY_RESOURCE'):
			dump_dict['Resource directory']=[];dump_dict['Resource directory'].append(self.DIRECTORY_ENTRY_RESOURCE.struct.dump_dict())
			for res_type in self.DIRECTORY_ENTRY_RESOURCE.entries:
				resource_type_dict={}
				if res_type.name is not None:resource_type_dict['Name']=res_type.name
				else:resource_type_dict['Id']=res_type.struct.Id,RESOURCE_TYPE.get(res_type.struct.Id,'-')
				resource_type_dict.update(res_type.struct.dump_dict());dump_dict['Resource directory'].append(resource_type_dict)
				if hasattr(res_type,'directory'):
					directory_list=[];directory_list.append(res_type.directory.struct.dump_dict());dump_dict['Resource directory'].append(directory_list)
					for resource_id in res_type.directory.entries:
						resource_id_dict={}
						if resource_id.name is not None:resource_id_dict['Name']=resource_id.name
						else:resource_id_dict['Id']=resource_id.struct.Id
						resource_id_dict.update(resource_id.struct.dump_dict());directory_list.append(resource_id_dict)
						if hasattr(resource_id,'directory'):
							resource_id_list=[];resource_id_list.append(resource_id.directory.struct.dump_dict());directory_list.append(resource_id_list)
							for resource_lang in resource_id.directory.entries:
								if hasattr(resource_lang,'data'):resource_lang_dict={};resource_lang_dict['LANG']=resource_lang.data.lang;resource_lang_dict['SUBLANG']=resource_lang.data.sublang;resource_lang_dict['LANG_NAME']=LANG.get(resource_lang.data.lang,'*unknown*');resource_lang_dict['SUBLANG_NAME']=get_sublang_name_for_lang(resource_lang.data.lang,resource_lang.data.sublang);resource_lang_dict.update(resource_lang.struct.dump_dict());resource_lang_dict.update(resource_lang.data.struct.dump_dict());resource_id_list.append(resource_lang_dict)
							if hasattr(resource_id.directory,'strings')and resource_id.directory.strings:
								for(idx,res_string)in list(resource_id.directory.strings.items()):resource_id_list.append(res_string.encode('unicode-escape','backslashreplace').decode('ascii'))
		if hasattr(self,'DIRECTORY_ENTRY_TLS')and self.DIRECTORY_ENTRY_TLS and self.DIRECTORY_ENTRY_TLS.struct:dump_dict['TLS']=self.DIRECTORY_ENTRY_TLS.struct.dump_dict()
		if hasattr(self,'DIRECTORY_ENTRY_LOAD_CONFIG')and self.DIRECTORY_ENTRY_LOAD_CONFIG and self.DIRECTORY_ENTRY_LOAD_CONFIG.struct:dump_dict['LOAD_CONFIG']=self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.dump_dict()
		if hasattr(self,'DIRECTORY_ENTRY_DEBUG'):
			dump_dict['Debug information']=[]
			for dbg in self.DIRECTORY_ENTRY_DEBUG:dbg_dict={};dump_dict['Debug information'].append(dbg_dict);dbg_dict.update(dbg.struct.dump_dict());dbg_dict['Type']=DEBUG_TYPE.get(dbg.struct.Type,dbg.struct.Type)
		if self.has_relocs():
			dump_dict['Base relocations']=[]
			for base_reloc in self.DIRECTORY_ENTRY_BASERELOC:
				base_reloc_list=[];dump_dict['Base relocations'].append(base_reloc_list);base_reloc_list.append(base_reloc.struct.dump_dict())
				for reloc in base_reloc.entries:
					reloc_dict={};base_reloc_list.append(reloc_dict);reloc_dict['RVA']=reloc.rva
					try:reloc_dict['Type']=RELOCATION_TYPE[reloc.type][16:]
					except KeyError:reloc_dict['Type']=reloc.type
		return dump_dict
	def get_physical_by_rva(self,rva):
		try:return self.get_offset_from_rva(rva)
		except Exception:return
	def get_data_from_dword(self,dword):return struct.pack('<L',dword&4294967295)
	def get_dword_from_data(self,data,offset):
		if(offset+1)*4>len(data):return
		return struct.unpack('<I',data[offset*4:(offset+1)*4])[0]
	def get_dword_at_rva(self,rva):
		try:return self.get_dword_from_data(self.get_data(rva,4),0)
		except PEFormatError:return
	def get_dword_from_offset(self,offset):
		if offset+4>len(self.__data__):return
		return self.get_dword_from_data(self.__data__[offset:offset+4],0)
	def set_dword_at_rva(self,rva,dword):return self.set_bytes_at_rva(rva,self.get_data_from_dword(dword))
	def set_dword_at_offset(self,offset,dword):return self.set_bytes_at_offset(offset,self.get_data_from_dword(dword))
	def get_data_from_word(self,word):return struct.pack('<H',word)
	def get_word_from_data(self,data,offset):
		if(offset+1)*2>len(data):return
		return struct.unpack('<H',data[offset*2:(offset+1)*2])[0]
	def get_word_at_rva(self,rva):
		try:return self.get_word_from_data(self.get_data(rva)[:2],0)
		except PEFormatError:return
	def get_word_from_offset(self,offset):
		if offset+2>len(self.__data__):return
		return self.get_word_from_data(self.__data__[offset:offset+2],0)
	def set_word_at_rva(self,rva,word):return self.set_bytes_at_rva(rva,self.get_data_from_word(word))
	def set_word_at_offset(self,offset,word):return self.set_bytes_at_offset(offset,self.get_data_from_word(word))
	def get_data_from_qword(self,word):return struct.pack('<Q',word)
	def get_qword_from_data(self,data,offset):
		if(offset+1)*8>len(data):return
		return struct.unpack('<Q',data[offset*8:(offset+1)*8])[0]
	def get_qword_at_rva(self,rva):
		try:return self.get_qword_from_data(self.get_data(rva)[:8],0)
		except PEFormatError:return
	def get_qword_from_offset(self,offset):
		if offset+8>len(self.__data__):return
		return self.get_qword_from_data(self.__data__[offset:offset+8],0)
	def set_qword_at_rva(self,rva,qword):return self.set_bytes_at_rva(rva,self.get_data_from_qword(qword))
	def set_qword_at_offset(self,offset,qword):return self.set_bytes_at_offset(offset,self.get_data_from_qword(qword))
	def set_bytes_at_rva(self,rva,data):
		if not isinstance(data,bytes):raise TypeError('data should be of type: bytes')
		offset=self.get_physical_by_rva(rva)
		if not offset:return False
		return self.set_bytes_at_offset(offset,data)
	def set_bytes_at_offset(self,offset,data):
		if not isinstance(data,bytes):raise TypeError('data should be of type: bytes')
		if 0<=offset<len(self.__data__):self.set_data_bytes(offset,data)
		else:return False
		return True
	def set_data_bytes(self,offset,data):
		if not isinstance(self.__data__,bytearray):new_data=bytearray(self.__data__);self._close_data();self.__data__=new_data
		self.__data__[offset:offset+len(data)]=data
	def merge_modified_section_data(self):
		for section in self.sections:
			section_data_start=self.adjust_PointerToRawData(section.PointerToRawData);section_data_end=section_data_start+section.SizeOfRawData
			if section_data_start<len(self.__data__)and section_data_end<len(self.__data__):self.set_data_bytes(section_data_start,section.get_data())
	def relocate_image(self,new_ImageBase):
		relocation_difference=new_ImageBase-self.OPTIONAL_HEADER.ImageBase
		if len(self.OPTIONAL_HEADER.DATA_DIRECTORY)>=6 and self.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size:
			if not hasattr(self,'DIRECTORY_ENTRY_BASERELOC'):self.parse_data_directories(directories=[DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']])
			if not hasattr(self,'DIRECTORY_ENTRY_BASERELOC'):self.__warnings.append('Relocating image but PE does not have (or pefile cannot parse) a DIRECTORY_ENTRY_BASERELOC')
			else:
				for reloc in self.DIRECTORY_ENTRY_BASERELOC:
					entry_idx=0
					while entry_idx<len(reloc.entries):
						entry=reloc.entries[entry_idx];entry_idx+=1
						if entry.type==RELOCATION_TYPE['IMAGE_REL_BASED_ABSOLUTE']:0
						elif entry.type==RELOCATION_TYPE['IMAGE_REL_BASED_HIGH']:self.set_word_at_rva(entry.rva,self.get_word_at_rva(entry.rva)+relocation_difference>>16&65535)
						elif entry.type==RELOCATION_TYPE['IMAGE_REL_BASED_LOW']:self.set_word_at_rva(entry.rva,self.get_word_at_rva(entry.rva)+relocation_difference&65535)
						elif entry.type==RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']:self.set_dword_at_rva(entry.rva,self.get_dword_at_rva(entry.rva)+relocation_difference)
						elif entry.type==RELOCATION_TYPE['IMAGE_REL_BASED_HIGHADJ']:
							if entry_idx==len(reloc.entries):break
							next_entry=reloc.entries[entry_idx];entry_idx+=1;self.set_word_at_rva(entry.rva,((self.get_word_at_rva(entry.rva)<<16)+next_entry.rva+relocation_difference&4294901760)>>16)
						elif entry.type==RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']:self.set_qword_at_rva(entry.rva,self.get_qword_at_rva(entry.rva)+relocation_difference)
			self.OPTIONAL_HEADER.ImageBase=new_ImageBase
			if hasattr(self,'DIRECTORY_ENTRY_IMPORT'):
				for dll in self.DIRECTORY_ENTRY_IMPORT:
					for func in dll.imports:func.address+=relocation_difference
			if hasattr(self,'DIRECTORY_ENTRY_TLS'):self.DIRECTORY_ENTRY_TLS.struct.StartAddressOfRawData+=relocation_difference;self.DIRECTORY_ENTRY_TLS.struct.EndAddressOfRawData+=relocation_difference;self.DIRECTORY_ENTRY_TLS.struct.AddressOfIndex+=relocation_difference;self.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks+=relocation_difference
			if hasattr(self,'DIRECTORY_ENTRY_LOAD_CONFIG'):
				load_config=self.DIRECTORY_ENTRY_LOAD_CONFIG.struct
				if hasattr(load_config,'LockPrefixTable')and load_config.LockPrefixTable:load_config.LockPrefixTable+=relocation_difference
				if hasattr(load_config,'EditList')and load_config.EditList:load_config.EditList+=relocation_difference
				if hasattr(load_config,'SecurityCookie')and load_config.SecurityCookie:load_config.SecurityCookie+=relocation_difference
				if hasattr(load_config,'SEHandlerTable')and load_config.SEHandlerTable:load_config.SEHandlerTable+=relocation_difference
				if hasattr(load_config,'GuardCFCheckFunctionPointer')and load_config.GuardCFCheckFunctionPointer:load_config.GuardCFCheckFunctionPointer+=relocation_difference
				if hasattr(load_config,'GuardCFDispatchFunctionPointer')and load_config.GuardCFDispatchFunctionPointer:load_config.GuardCFDispatchFunctionPointer+=relocation_difference
				if hasattr(load_config,'GuardCFFunctionTable')and load_config.GuardCFFunctionTable:load_config.GuardCFFunctionTable+=relocation_difference
				if hasattr(load_config,'GuardAddressTakenIatEntryTable')and load_config.GuardAddressTakenIatEntryTable:load_config.GuardAddressTakenIatEntryTable+=relocation_difference
				if hasattr(load_config,'GuardLongJumpTargetTable')and load_config.GuardLongJumpTargetTable:load_config.GuardLongJumpTargetTable+=relocation_difference
				if hasattr(load_config,'DynamicValueRelocTable')and load_config.DynamicValueRelocTable:load_config.DynamicValueRelocTable+=relocation_difference
				if self.PE_TYPE==OPTIONAL_HEADER_MAGIC_PE_PLUS and hasattr(load_config,'CHPEMetadataPointer')and load_config.CHPEMetadataPointer:load_config.CHPEMetadataPointer+=relocation_difference
				if hasattr(load_config,'GuardRFFailureRoutine')and load_config.GuardRFFailureRoutine:load_config.GuardRFFailureRoutine+=relocation_difference
				if hasattr(load_config,'GuardRFFailureRoutineFunctionPointer')and load_config.GuardRFFailureRoutineFunctionPointer:load_config.GuardRFVerifyStackPointerFunctionPointer+=relocation_difference
				if hasattr(load_config,'GuardRFVerifyStackPointerFunctionPointer')and load_config.GuardRFVerifyStackPointerFunctionPointer:load_config.GuardRFVerifyStackPointerFunctionPointer+=relocation_difference
				if hasattr(load_config,'EnclaveConfigurationPointer')and load_config.EnclaveConfigurationPointer:load_config.EnclaveConfigurationPointer+=relocation_difference
				if hasattr(load_config,'VolatileMetadataPointer')and load_config.VolatileMetadataPointer:load_config.VolatileMetadataPointer+=relocation_difference
				if hasattr(load_config,'GuardEHContinuationTable')and load_config.GuardEHContinuationTable:load_config.GuardEHContinuationTable+=relocation_difference
				if hasattr(load_config,'GuardXFGCheckFunctionPointer')and load_config.GuardXFGCheckFunctionPointer:load_config.GuardXFGCheckFunctionPointer+=relocation_difference
				if hasattr(load_config,'GuardXFGDispatchFunctionPointer')and load_config.GuardXFGDispatchFunctionPointer:load_config.GuardXFGDispatchFunctionPointer+=relocation_difference
				if hasattr(load_config,'GuardXFGTableDispatchFunctionPointer')and load_config.GuardXFGTableDispatchFunctionPointer:load_config.GuardXFGTableDispatchFunctionPointer+=relocation_difference
				if hasattr(load_config,'CastGuardOsDeterminedFailureMode')and load_config.CastGuardOsDeterminedFailureMode:load_config.CastGuardOsDeterminedFailureMode+=relocation_difference
				if hasattr(load_config,'GuardMemcpyFunctionPointer')and load_config.GuardMemcpyFunctionPointer:load_config.GuardMemcpyFunctionPointer+=relocation_difference
	def verify_checksum(self):return self.OPTIONAL_HEADER.CheckSum==self.generate_checksum()
	def generate_checksum(self):
		new_data=self.write();self._close_data();self.__data__=new_data;checksum_offset=self.OPTIONAL_HEADER.get_file_offset()+64;checksum=0;remainder=len(self.__data__)%4;data_len=len(self.__data__)+(4-remainder)*(remainder!=0)
		for i in range(data_len//4):
			if i==checksum_offset//4:continue
			if i+1==data_len//4 and remainder:dword=struct.unpack('I',self.__data__[i*4:]+b'\x00'*(4-remainder))[0]
			else:dword=struct.unpack('I',self.__data__[i*4:i*4+4])[0]
			checksum+=dword
			if checksum>=2**32:checksum=(checksum&4294967295)+(checksum>>32)
		checksum=(checksum&65535)+(checksum>>16);checksum=checksum+(checksum>>16);checksum=checksum&65535;return checksum+len(self.__data__)
	def is_exe(self):
		EXE_flag=IMAGE_CHARACTERISTICS['IMAGE_FILE_EXECUTABLE_IMAGE']
		if not self.is_dll()and not self.is_driver()and EXE_flag&self.FILE_HEADER.Characteristics==EXE_flag:return True
		return False
	def is_dll(self):
		DLL_flag=IMAGE_CHARACTERISTICS['IMAGE_FILE_DLL']
		if DLL_flag&self.FILE_HEADER.Characteristics==DLL_flag:return True
		return False
	def is_driver(self):
		if not hasattr(self,'DIRECTORY_ENTRY_IMPORT'):self.parse_data_directories(directories=[DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
		if not hasattr(self,'DIRECTORY_ENTRY_IMPORT'):return False
		system_DLLs={b'ntoskrnl.exe',b'hal.dll',b'ndis.sys',b'bootvid.dll',b'kdcom.dll'}
		if system_DLLs.intersection({imp.dll.lower()for imp in self.DIRECTORY_ENTRY_IMPORT}):return True
		driver_like_section_names={b'page',b'paged'}
		if driver_like_section_names.intersection({section.Name.lower().rstrip(b'\x00')for section in self.sections})and self.OPTIONAL_HEADER.Subsystem in(SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_NATIVE'],SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_NATIVE_WINDOWS']):return True
		return False
	def get_overlay_data_start_offset(self):
		largest_offset_and_size=0,0
		def update_if_sum_is_larger_and_within_file(offset_and_size,file_size=len(self.__data__)):
			if sum(largest_offset_and_size)<sum(offset_and_size)<=file_size:return offset_and_size
			return largest_offset_and_size
		if hasattr(self,'OPTIONAL_HEADER'):largest_offset_and_size=update_if_sum_is_larger_and_within_file((self.OPTIONAL_HEADER.get_file_offset(),self.FILE_HEADER.SizeOfOptionalHeader))
		for section in self.sections:largest_offset_and_size=update_if_sum_is_larger_and_within_file((section.PointerToRawData,section.SizeOfRawData))
		skip_directories=[DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
		for(idx,directory)in enumerate(self.OPTIONAL_HEADER.DATA_DIRECTORY):
			if idx in skip_directories:continue
			try:largest_offset_and_size=update_if_sum_is_larger_and_within_file((self.get_offset_from_rva(directory.VirtualAddress),directory.Size))
			except PEFormatError:continue
		if len(self.__data__)>sum(largest_offset_and_size):return sum(largest_offset_and_size)
	def get_overlay(self):
		overlay_data_offset=self.get_overlay_data_start_offset()
		if overlay_data_offset is not None:return self.__data__[overlay_data_offset:]
	def trim(self):
		overlay_data_offset=self.get_overlay_data_start_offset()
		if overlay_data_offset is not None:return self.__data__[:overlay_data_offset]
		return self.__data__[:]
	def adjust_PointerToRawData(self,val):
		if self.OPTIONAL_HEADER.FileAlignment>=MIN_VALID_FILE_ALIGNMENT:
			if self.FileAlignment_Warning is False and not power_of_two(self.OPTIONAL_HEADER.FileAlignment):self.__warnings.append('If FileAlignment > 0x200 it should be a power of 2. Value: %x'%self.OPTIONAL_HEADER.FileAlignment);self.FileAlignment_Warning=True
		return val&~511
	def adjust_SectionAlignment(self,val,section_alignment,file_alignment):
		if section_alignment<4096:
			if file_alignment!=section_alignment and self.SectionAlignment_Warning is False:self.__warnings.append(f"If SectionAlignment(0x{section_alignment:x}) < 0x1000 it should equal FileAlignment(0x{file_alignment:x})");self.SectionAlignment_Warning=True
		return cache_adjust_SectionAlignment(val,section_alignment,file_alignment)

"""

######################################################################################           ######################################################################################
###################################################################################### PEFILE.PY ######################################################################################
######################################################################################           ######################################################################################

"""

# System DLLs
_kernel32 = ctypes.WinDLL('kernel32')
_msvcrt = ctypes.CDLL('msvcrt')

# Check if the current machine is x64 or x86
IS_X64 = ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulonglong)

# Type declarations
PWORD = ctypes.POINTER(wintypes.WORD)
PDWORD = ctypes.POINTER(wintypes.DWORD)
PHMODULE = ctypes.POINTER(wintypes.HMODULE)
LONG_PTR = ctypes.c_longlong if IS_X64 else wintypes.LONG
ULONG_PTR2 = ctypes.c_ulong
ULONG_PTR = ctypes.c_ulonglong if IS_X64 else wintypes.DWORD
UINT_PTR = ctypes.c_ulonglong if IS_X64 else ctypes.c_uint
SIZE_T = ULONG_PTR
POINTER_TYPE = ULONG_PTR
POINTER_TYPE2 = ULONG_PTR2
LP_POINTER_TYPE = ctypes.POINTER(POINTER_TYPE)
FARPROC = ctypes.CFUNCTYPE(None)
PFARPROC = ctypes.POINTER(FARPROC)
c_uchar_p = ctypes.POINTER(ctypes.c_ubyte)
c_ushort_p = ctypes.POINTER(ctypes.c_ushort)

# Generic Constants
NULL = 0

# Win32/Module-specific constants
IMAGE_SIZEOF_SHORT_NAME = 8
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_SIZEOF_SECTION_HEADER = 40

# Struct declarations
class IMAGE_SECTION_HEADER_MISC(ctypes.Union):
    _fields_ = [
        ('PhysicalAddress', wintypes.DWORD),
        ('VirtualSize', wintypes.DWORD),
    ]


class IMAGE_SECTION_HEADER(ctypes.Structure):
    _anonymous_ = ('Misc',)
    _fields_ = [
        ('Name', wintypes.BYTE * IMAGE_SIZEOF_SHORT_NAME),
        ('Misc', IMAGE_SECTION_HEADER_MISC),
        ('VirtualAddress', wintypes.DWORD),
        ('SizeOfRawData', wintypes.DWORD),
        ('PointerToRawData', wintypes.DWORD),
        ('PointerToRelocations', wintypes.DWORD),
        ('PointerToLinenumbers', wintypes.DWORD),
        ('NumberOfRelocations', wintypes.WORD),
        ('NumberOfLinenumbers', wintypes.WORD),
        ('Characteristics', wintypes.DWORD),
    ]


PIMAGE_SECTION_HEADER = ctypes.POINTER(IMAGE_SECTION_HEADER)


class IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_ = [
        ('e_magic', wintypes.WORD),
        ('e_cblp', wintypes.WORD),
        ('e_cp', wintypes.WORD),
        ('e_crlc', wintypes.WORD),
        ('e_cparhdr', wintypes.WORD),
        ('e_minalloc', wintypes.WORD),
        ('e_maxalloc', wintypes.WORD),
        ('e_ss', wintypes.WORD),
        ('e_sp', wintypes.WORD),
        ('e_csum', wintypes.WORD),
        ('e_ip', wintypes.WORD),
        ('e_cs', wintypes.WORD),
        ('e_lfarlc', wintypes.WORD),
        ('e_ovno', wintypes.WORD),
        ('e_res', wintypes.WORD * 4),
        ('e_oemid', wintypes.WORD),
        ('e_oeminfo', wintypes.WORD),
        ('e_res2', wintypes.WORD * 10),
        ('e_lfanew', wintypes.LONG),
    ]


PIMAGE_DOS_HEADER = ctypes.POINTER(IMAGE_DOS_HEADER)


class IMAGE_TLS_CALLBACK(ctypes.c_void_p):
    """void NTAPI IMAGE_TLS_CALLBACK(PVOID DllHandle, DWORD Reason, PVOID Reserved)"""


PIMAGE_TLS_CALLBACK = ctypes.POINTER(IMAGE_TLS_CALLBACK)


class IMAGE_TLS_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ('StartAddressOfRawData', ctypes.c_ulonglong),
        ('EndAddressOfRawData', ctypes.c_ulonglong),
        ('AddressOfIndex', ctypes.c_ulonglong),
        ('AddressOfCallBacks', ctypes.c_ulonglong),
        ('SizeOfZeroFill', wintypes.DWORD),
        ('Characteristics', wintypes.DWORD),
    ]


PIMAGE_TLS_DIRECTORY = ctypes.POINTER(IMAGE_TLS_DIRECTORY)


class IMAGE_DATA_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ('VirtualAddress', wintypes.DWORD),
        ('Size', wintypes.DWORD),
    ]


PIMAGE_DATA_DIRECTORY = ctypes.POINTER(IMAGE_DATA_DIRECTORY)


class IMAGE_BASE_RELOCATION(ctypes.Structure):
    _fields_ = [
        ('VirtualAddress', wintypes.DWORD),
        ('SizeOfBlock', wintypes.DWORD),
    ]


PIMAGE_BASE_RELOCATION = ctypes.POINTER(IMAGE_BASE_RELOCATION)


class IMAGE_EXPORT_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ('Characteristics', wintypes.DWORD),
        ('TimeDateStamp', wintypes.DWORD),
        ('MajorVersion', wintypes.WORD),
        ('MinorVersion', wintypes.WORD),
        ('Name', wintypes.DWORD),
        ('Base', wintypes.DWORD),
        ('NumberOfFunctions', wintypes.DWORD),
        ('NumberOfNames', wintypes.DWORD),
        ('AddressOfFunctions', wintypes.DWORD),
        ('AddressOfNames', wintypes.DWORD),
        ('AddressOfNamesOrdinals', wintypes.DWORD),
    ]


PIMAGE_EXPORT_DIRECTORY = ctypes.POINTER(IMAGE_EXPORT_DIRECTORY)


class IMAGE_IMPORT_DESCRIPTOR_START(ctypes.Union):
    _fields_ = [
        ('Characteristics', wintypes.DWORD),
        ('OriginalFirstThunk', wintypes.DWORD),
    ]


class IMAGE_IMPORT_DESCRIPTOR(ctypes.Structure):
    _anonymous_ = ('DUMMY',)
    _fields_ = [
        ('DUMMY', IMAGE_IMPORT_DESCRIPTOR_START),
        ('TimeDateStamp', wintypes.DWORD),
        ('ForwarderChain', wintypes.DWORD),
        ('Name', wintypes.DWORD),
        ('FirstThunk', wintypes.DWORD),
    ]


PIMAGE_IMPORT_DESCRIPTOR = ctypes.POINTER(IMAGE_IMPORT_DESCRIPTOR)


class IMAGE_IMPORT_BY_NAME(ctypes.Structure):
    _fields_ = [
        ('Hint', wintypes.WORD),
        ('Name', ctypes.ARRAY(wintypes.BYTE, 1)),
    ]


PIMAGE_IMPORT_BY_NAME = ctypes.POINTER(IMAGE_IMPORT_BY_NAME)


class IMAGE_OPTIONAL_HEADER(ctypes.Structure):
    _fields_ = [
        ('Magic', wintypes.WORD),
        ('MajorLinkerVersion', wintypes.BYTE),
        ('MinorLinkerVersion', wintypes.BYTE),
        ('SizeOfCode', wintypes.DWORD),
        ('SizeOfInitializedData', wintypes.DWORD),
        ('SizeOfUninitializedData', wintypes.DWORD),
        ('AddressOfEntryPoint', wintypes.DWORD),
        ('BaseOfCode', wintypes.DWORD),
        ('BaseOfData', wintypes.DWORD),
        ('ImageBase', POINTER_TYPE),
        ('SectionAlignment', wintypes.DWORD),
        ('FileAlignment', wintypes.DWORD),
        ('MajorOperatingSystemVersion', wintypes.WORD),
        ('MinorOperatingSystemVersion', wintypes.WORD),
        ('MajorImageVersion', wintypes.WORD),
        ('MinorImageVersion', wintypes.WORD),
        ('MajorSubsystemVersion', wintypes.WORD),
        ('MinorSubsystemVersion', wintypes.WORD),
        ('Reserved1', wintypes.DWORD),
        ('SizeOfImage', wintypes.DWORD),
        ('SizeOfHeaders', wintypes.DWORD),
        ('CheckSum', wintypes.DWORD),
        ('Subsystem', wintypes.WORD),
        ('DllCharacteristics', wintypes.WORD),
        ('SizeOfStackReserve', POINTER_TYPE),
        ('SizeOfStackCommit', POINTER_TYPE),
        ('SizeOfHeapReserve', POINTER_TYPE),
        ('SizeOfHeapCommit', POINTER_TYPE),
        ('LoaderFlags', wintypes.DWORD),
        ('NumberOfRvaAndSizes', wintypes.DWORD),
        ('DataDirectory', IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    ]


PIMAGE_OPTIONAL_HEADER = ctypes.POINTER(IMAGE_OPTIONAL_HEADER)


class IMAGE_FILE_HEADER(ctypes.Structure):
    _fields_ = [
        ('Machine', wintypes.WORD),
        ('NumberOfSections', wintypes.WORD),
        ('TimeDateStamp', wintypes.DWORD),
        ('PointerToSymbolTable', wintypes.DWORD),
        ('NumberOfSymbols', wintypes.DWORD),
        ('SizeOfOptionalHeader', wintypes.WORD),
        ('Characteristics', wintypes.WORD),
    ]


PIMAGE_FILE_HEADER = ctypes.POINTER(IMAGE_FILE_HEADER)


class IMAGE_NT_HEADERS(ctypes.Structure):
    _fields_ = [
        ('Signature', wintypes.DWORD),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER),
    ]


PIMAGE_NT_HEADERS = ctypes.POINTER(IMAGE_NT_HEADERS)

# Win32 API Function Prototypes
VirtualAlloc = _kernel32.VirtualAlloc
VirtualAlloc.restype = wintypes.LPVOID
VirtualAlloc.argtypes = [wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.DWORD]

VirtualFree = _kernel32.VirtualFree
VirtualFree.restype = wintypes.BOOL
VirtualFree.argtypes = [wintypes.LPVOID, SIZE_T, wintypes.DWORD]

VirtualProtect = _kernel32.VirtualProtect
VirtualProtect.restype = wintypes.BOOL
VirtualProtect.argtypes = [wintypes.LPVOID, SIZE_T, wintypes.DWORD, PDWORD]

HeapAlloc = _kernel32.HeapAlloc
HeapAlloc.restype = wintypes.LPVOID
HeapAlloc.argtypes = [wintypes.HANDLE, wintypes.DWORD, SIZE_T]

GetProcessHeap = _kernel32.GetProcessHeap
GetProcessHeap.restype = wintypes.HANDLE
GetProcessHeap.argtypes = []

HeapFree = _kernel32.HeapFree
HeapFree.restype = wintypes.BOOL
HeapFree.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID]

GetProcAddress = _kernel32.GetProcAddress
GetProcAddress.restype = FARPROC
GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]

LoadLibraryA = _kernel32.LoadLibraryA
LoadLibraryA.restype = wintypes.HMODULE
LoadLibraryA.argtypes = [wintypes.LPCSTR]

LoadLibraryW = _kernel32.LoadLibraryW
LoadLibraryW.restype = wintypes.HMODULE
LoadLibraryW.argtypes = [wintypes.LPCWSTR]

FreeLibrary = _kernel32.FreeLibrary
FreeLibrary.restype = wintypes.BOOL
FreeLibrary.argtypes = [wintypes.HMODULE]

IsBadReadPtr = _kernel32.IsBadReadPtr
IsBadReadPtr.restype = wintypes.BOOL
IsBadReadPtr.argtypes = [wintypes.LPCVOID, UINT_PTR]

realloc = _msvcrt.realloc
realloc.restype = ctypes.c_void_p
realloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t]

# Type declarations
DllEntryProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HINSTANCE, wintypes.DWORD, wintypes.LPVOID)
PDllEntryProc = ctypes.POINTER(DllEntryProc)
TLSExecProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HINSTANCE, wintypes.DWORD, wintypes.LPVOID)
PTLSExecProc = ctypes.POINTER(TLSExecProc)
HMEMORYMODULE = wintypes.HMODULE
ExeEntryProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.LPVOID)
PExeEntryProc = ctypes.POINTER(ExeEntryProc)

# Constants
MEM_COMMIT = 0x00001000
MEM_DECOMMIT = 0x4000
MEM_RELEASE = 0x8000
MEM_RESERVE = 0x00002000
MEM_FREE = 0x10000
MEM_MAPPED = 0x40000
MEM_RESET = 0x00080000
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOCACHE = 0x200

ProtectionFlags = (
    (
        (PAGE_NOACCESS, PAGE_WRITECOPY),
        (PAGE_READONLY, PAGE_READWRITE),
    ),
    (
        (PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY),
        (PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE),
    ),
)

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8
IMAGE_DIRECTORY_ENTRY_TLS = 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11
IMAGE_DIRECTORY_ENTRY_IAT = 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14
DLL_PROCESS_ATTACH = 1
DLL_THREAD_ATTACH = 2
DLL_THREAD_DETACH = 3
DLL_PROCESS_DETACH = 0
INVALID_HANDLE_VALUE = -1
IMAGE_SIZEOF_BASE_RELOCATION = ctypes.sizeof(IMAGE_BASE_RELOCATION)
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGH = 1
IMAGE_REL_BASED_LOW = 2
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_HIGHADJ = 4
IMAGE_REL_BASED_MIPS_JMPADDR = 5
IMAGE_REL_BASED_MIPS_JMPADDR16 = 9
IMAGE_REL_BASED_IA64_IMM64 = 9
IMAGE_REL_BASED_DIR64 = 10
_IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
_IMAGE_ORDINAL_FLAG32 = 0x80000000
_IMAGE_ORDINAL64 = lambda o: (o & 0xFFFF)
_IMAGE_ORDINAL32 = lambda o: (o & 0xFFFF)
_IMAGE_SNAP_BY_ORDINAL64 = lambda o: ((o & _IMAGE_ORDINAL_FLAG64) != 0)
_IMAGE_SNAP_BY_ORDINAL32 = lambda o: ((o & _IMAGE_ORDINAL_FLAG32) != 0)
IMAGE_ORDINAL = _IMAGE_ORDINAL64 if IS_X64 else _IMAGE_ORDINAL32
IMAGE_SNAP_BY_ORDINAL = _IMAGE_SNAP_BY_ORDINAL64 if IS_X64 else _IMAGE_SNAP_BY_ORDINAL32
IMAGE_ORDINAL_FLAG = _IMAGE_ORDINAL_FLAG64 if IS_X64 else _IMAGE_ORDINAL_FLAG32
IMAGE_DOS_SIGNATURE = 0x5A4D  # MZ
IMAGE_OS2_SIGNATURE = 0x454E  # NE
IMAGE_OS2_SIGNATURE_LE = 0x454C  # LE
IMAGE_VXD_SIGNATURE = 0x454C  # LE
IMAGE_NT_SIGNATURE = 0x00004550  # PE00


class MEMORYMODULE(ctypes.Structure):
    _fields_ = [
        ('headers', PIMAGE_NT_HEADERS),
        ('codeBase', ctypes.c_void_p),
        ('modules', PHMODULE),
        ('numModules', ctypes.c_int),
        ('initialized', ctypes.c_int),
    ]


PMEMORYMODULE = ctypes.POINTER(MEMORYMODULE)


def as_unsigned_buffer(sz=None, indata=None):
    if sz is None:
        if indata is None:
            raise Exception('Must specify initial data or a buffer size.')
        sz = len(indata)
    rtype = (ctypes.c_ubyte * sz)
    if indata is None:
        return rtype
    else:
        tindata = type(indata)
        if tindata is int:
            return rtype.from_address(indata)
        elif tindata in [ctypes.c_void_p, wintypes.DWORD, POINTER_TYPE] or (
            hasattr(indata, 'value') and type(indata.value) is int
        ):
            return rtype.from_address(indata.value)
        else:
            return rtype.from_address(ctypes.addressof(indata))


def create_unsigned_buffer(sz, indata):
    res = as_unsigned_buffer(sz)()
    for i, c in enumerate(indata):
        if isinstance(c, str):
            c = ord(c)
        res[i] = c
    return res


def get_proc_address(handle, function_name):
    _kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    _kernel32.GetProcAddress.restype = ctypes.c_void_p
    address = _kernel32.GetProcAddress(handle, function_name)
    return address


class MemoryModule(PE):
    _foffsets_ = {}

    def __init__(self, name=None, data=None):
        PE.__init__(self, name, data)
        self.load_module()

    def exec_pe(self):
        codebase = self._codebase_addr
        entry_addr = self.python_memory_module.contents.headers.contents.OptionalHeader.AddressOfEntryPoint
        if entry_addr != 0:
            entry_addr += codebase
            if self.is_exe():
                exe_entry = ExeEntryProc(entry_addr)
                if not bool(exe_entry):
                    self.free_library()
                    raise WindowsError('exe has no entry point.\n')
                try:
                    success = exe_entry(entry_addr)
                except Exception as e:
                    print(e)
            elif self.is_dll():
                dll_entry = DllEntryProc(entry_addr)
                if not bool(dll_entry):
                    self.free_library()
                    raise WindowsError('dll has no entry point.\n')
                try:
                    success = dll_entry(codebase, DLL_PROCESS_ATTACH, 0)
                except Exception as e:
                    print(e)
            if not bool(success):
                if self.is_dll():
                    self.free_library()
                    raise WindowsError('dll could not be loaded.')
                else:
                    self.free_exe()
                    raise WindowsError('exe could not be loaded')
            self.python_memory_module.contents.initialized = 1

    def load_module(self):
        if not self.is_exe() and not self.is_dll():
            raise WindowsError('The specified module does not appear to be an exe nor a dll.')
        if self.PE_TYPE == 267 and IS_X64:
            raise WindowsError(
                'The exe you attempted to load appears to be a 32-bit exe, but you are using a 64-bit version of Python.'
            )
        elif self.PE_TYPE == 523 and not IS_X64:
            raise WindowsError(
                'The exe you attempted to load appears to be a 64-bit exe, but you are using a 32-bit version of Python.'
            )
        self._codebase_addr = VirtualAlloc(
            self.OPTIONAL_HEADER.ImageBase,
            self.OPTIONAL_HEADER.SizeOfImage,
            MEM_RESERVE,
            PAGE_READWRITE,
        )
        if not bool(self._codebase_addr):
            self._codebase_addr = VirtualAlloc(
                NULL,
                self.OPTIONAL_HEADER.SizeOfImage,
                MEM_RESERVE,
                PAGE_READWRITE,
            )
            if not bool(self._codebase_addr):
                raise WindowsError('Cannot reserve memory')
        codebase = self._codebase_addr
        self.python_memory_module = ctypes.cast(
            HeapAlloc(GetProcessHeap(), 0, ctypes.sizeof(MEMORYMODULE)), PMEMORYMODULE
        )
        self.python_memory_module.contents.codeBase = codebase
        self.python_memory_module.contents.numModules = 0
        self.python_memory_module.contents.modules = ctypes.cast(NULL, PHMODULE)
        self.python_memory_module.contents.initialized = 0
        # Committing memory.
        VirtualAlloc(
            codebase,
            self.OPTIONAL_HEADER.SizeOfImage,
            MEM_COMMIT,
            PAGE_READWRITE,
        )
        self._headers_addr = VirtualAlloc(
            codebase,
            self.OPTIONAL_HEADER.SizeOfHeaders,
            MEM_COMMIT,
            PAGE_READWRITE,
        )
        if not bool(self._headers_addr):
            raise WindowsError('Could not commit memory for PE Headers!')
        sz_headers = self.DOS_HEADER.e_lfanew + self.OPTIONAL_HEADER.SizeOfHeaders
        tmp_headers = create_unsigned_buffer(sz_headers, self.__data__[:sz_headers])
        if not ctypes.memmove(self._headers_addr, ctypes.cast(tmp_headers, ctypes.c_void_p), sz_headers):
            raise RuntimeError('ctypes.memmove failed')
        del tmp_headers
        self._headers_addr += self.DOS_HEADER.e_lfanew
        self.python_memory_module.contents.headers = ctypes.cast(self._headers_addr, PIMAGE_NT_HEADERS)
        self.python_memory_module.contents.headers.contents.OptionalHeader.ImageBase = POINTER_TYPE(
            self._codebase_addr
        )
        self.copy_sections()
        location_delta = codebase - self.OPTIONAL_HEADER.ImageBase
        if location_delta != 0:
            self.perform_base_relocations(location_delta)
        self.build_import_table()
        self.finalize_sections()
        self.execute_tls()
        my_thread = threading.Thread(target=self.exec_pe)
        my_thread.start()

    def image_first_section(self):
        return self._headers_addr + IMAGE_NT_HEADERS.OptionalHeader.offset + self.FILE_HEADER.SizeOfOptionalHeader

    def copy_sections(self):
        codebase = self._codebase_addr
        section_addr = self.image_first_section()
        num_sections = self.python_memory_module.contents.headers.contents.FileHeader.NumberOfSections
        for i in range(0, num_sections):
            if self.sections[i].SizeOfRawData == 0:
                size = self.OPTIONAL_HEADER.SectionAlignment
                if size > 0:
                    dest_base_addr = codebase + self.sections[i].VirtualAddress
                    dest = VirtualAlloc(dest_base_addr, size, MEM_COMMIT, PAGE_READWRITE)
                    self.sections[i].Misc_PhysicalAddress = dest
                    ctypes.memset(dest, 0, size)
                continue
            size = self.sections[i].SizeOfRawData
            dest = VirtualAlloc(
                codebase + self.sections[i].VirtualAddress, size, MEM_COMMIT, PAGE_READWRITE
            )
            if dest <= 0:
                raise WindowsError(
                    'Error copying section no. %s to address: 0x%x',
                    self.sections[i].Name.decode('utf-8'),
                    dest,
                )
            self.sections[i].Misc_PhysicalAddress = dest
            tmp_data = create_unsigned_buffer(
                size, self.__data__[self.sections[i].PointerToRawData : (self.sections[i].PointerToRawData + size)]
            )
            if not ctypes.memmove(dest, tmp_data, size):
                raise RuntimeError('ctypes.memmove failed')
            del tmp_data
            i += 1

    def execute_tls(self):
        codebase = self._codebase_addr
        directory = self.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_TLS]
        if directory.VirtualAddress <= 0:
            return True
        tls_addr = codebase + directory.VirtualAddress
        tls = IMAGE_TLS_DIRECTORY.from_address(tls_addr)
        callback = IMAGE_TLS_CALLBACK.from_address(tls.AddressOfCallBacks)
        callback_addr = tls.AddressOfCallBacks
        while callback:
            tls_exec = TLSExecProc(callback.value)
            tls_res = tls_exec(ctypes.cast(codebase, wintypes.LPVOID), DLL_PROCESS_ATTACH, 0)
            if not bool(tls_res):
                raise WindowsError('TLS could not be executed.')
            else:
                callback_addr += ctypes.sizeof(ctypes.c_ulonglong)
                callback = IMAGE_TLS_CALLBACK.from_address(callback_addr)

    def finalize_sections(self):
        section_addr = self.image_first_section()
        num_sections = self.python_memory_module.contents.headers.contents.FileHeader.NumberOfSections
        image_offset = (
            POINTER_TYPE(self.python_memory_module.contents.headers.contents.OptionalHeader.ImageBase & 0xFFFFFFFF00000000)
            if IS_X64
            else POINTER_TYPE(0)
        )
        check_characteristic = lambda sect, flag: 1 if (sect.contents.Characteristics & flag) != 0 else 0
        get_phys_addr = lambda sect: section.contents.PhysicalAddress | image_offset.value
        for i in range(0, num_sections):
            section = ctypes.cast(section_addr, PIMAGE_SECTION_HEADER)
            size = section.contents.SizeOfRawData
            if size == 0:
                if check_characteristic(section, IMAGE_SCN_CNT_INITIALIZED_DATA):
                    size = self.python_memory_module.contents.headers.contents.OptionalHeader.SizeOfInitializedData
                elif check_characteristic(section, IMAGE_SCN_CNT_UNINITIALIZED_DATA):
                    size = self.python_memory_module.contents.headers.contents.OptionalHeader.SizeOfUninitializedData
                    continue
            if size == 0:
                continue
            old_protect = wintypes.DWORD(0)
            executable = check_characteristic(section, IMAGE_SCN_MEM_EXECUTE)
            readable = check_characteristic(section, IMAGE_SCN_MEM_READ)
            writeable = check_characteristic(section, IMAGE_SCN_MEM_WRITE)
            if check_characteristic(section, IMAGE_SCN_MEM_DISCARDABLE):
                addr = self.sections[i].Misc_PhysicalAddress
                VirtualFree(addr, section.contents.SizeOfRawData, MEM_DECOMMIT)
                continue
            protect = ProtectionFlags[executable][readable][writeable]
            if check_characteristic(section, IMAGE_SCN_MEM_NOT_CACHED):
                protect |= PAGE_NOCACHE
            size = section.contents.SizeOfRawData
            if size == 0:
                if check_characteristic(section, IMAGE_SCN_CNT_INITIALIZED_DATA):
                    size = self.python_memory_module.contents.headers.contents.OptionalHeader.SizeOfInitializedData
                elif check_characteristic(section, IMAGE_SCN_CNT_UNINITIALIZED_DATA):
                    size = self.python_memory_module.contents.headers.contents.OptionalHeader.SizeOfUninitializedData
            if size > 0:
                addr = self.sections[i].Misc_PhysicalAddress
                if VirtualProtect(addr, size, protect, ctypes.byref(old_protect)) == 0:
                    raise WindowsError('Error protecting memory page')
            section_addr += ctypes.sizeof(IMAGE_SECTION_HEADER)
            i += 1

    def perform_base_relocations(self, delta):
        codebase_addr = self._codebase_addr
        directory = self.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_BASERELOC]
        if directory.Size <= 0:
            return
        reloc_addr = codebase_addr + directory.VirtualAddress
        relocation = IMAGE_BASE_RELOCATION.from_address(reloc_addr)
        max_reloc = lambda r: (relocation.SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) // 2
        while relocation.VirtualAddress > 0:
            i = 0
            dest = codebase_addr + relocation.VirtualAddress
            rel_info_addr = reloc_addr + IMAGE_SIZEOF_BASE_RELOCATION
            while i < max_reloc(reloc_addr):
                rel_info = ctypes.c_ushort.from_address(rel_info_addr)
                type = rel_info.value >> 12
                offset = rel_info.value & 0xFFF
                if type == IMAGE_REL_BASED_HIGHLOW or (type == IMAGE_REL_BASED_DIR64 and IS_X64):
                    patch_addr_hl = ctypes.cast(dest + offset, LP_POINTER_TYPE)
                    patch_addr_hl.contents.value += delta
                else:
                    break
                rel_info_addr += 2
                i += 1
            reloc_addr += relocation.SizeOfBlock
            relocation = IMAGE_BASE_RELOCATION.from_address(reloc_addr)

    def build_import_table(self, dlopen=LoadLibraryW):
        codebase = self._codebase_addr
        directory = self.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_IMPORT]
        if directory.Size <= 0:
            return
        import_desc_addr = codebase + directory.VirtualAddress
        i = 0
        for i in range(0, len(self.DIRECTORY_ENTRY_IMPORT)):
            import_desc = directory.VirtualAddress
            entry_struct = self.DIRECTORY_ENTRY_IMPORT[i].struct
            entry_imports = self.DIRECTORY_ENTRY_IMPORT[i].imports
            dll = self.DIRECTORY_ENTRY_IMPORT[i].dll.decode('utf-8')
            if not bool(dll):
                hmod = dll
            else:
                hmod = dlopen(dll)
                if not bool(hmod):
                    raise WindowsError('Failed to load library, %s' % dll)
                result_realloc = realloc(
                    self.python_memory_module.contents.modules,
                    (self.python_memory_module.contents.modules._b_base_.numModules + 1)
                    * ctypes.sizeof(wintypes.HMODULE),
                )
                if not bool(result_realloc):
                    raise WindowsError('Failed to allocate additional room for our new import.')
                self.python_memory_module.contents.modules = ctypes.cast(
                    result_realloc, type(self.python_memory_module.contents.modules)
                )
                self.python_memory_module.contents.modules[
                    self.python_memory_module.contents.modules._b_base_.numModules
                ] = hmod
                self.python_memory_module.contents.modules._b_base_.numModules += 1
            thunk_ref_addr = func_ref_addr = codebase + entry_struct.FirstThunk
            if entry_struct.OriginalFirstThunk > 0:
                thunk_ref_addr = codebase + entry_struct.OriginalFirstThunk
            for j in range(0, len(entry_imports)):
                func_ref = ctypes.cast(func_ref_addr, PFARPROC)
                if entry_imports[j].import_by_ordinal is True:
                    import_ordinal = (
                        entry_imports[j].ordinal.decode('utf-8')
                        if hasattr(entry_imports[j].ordinal, 'decode')
                        else entry_imports[j].ordinal
                    )
                    func_ref.contents = GetProcAddress(hmod, ctypes.cast(import_ordinal, wintypes.LPCSTR))
                    address = func_ref.contents
                else:
                    import_name = entry_imports[j].name.decode('utf-8')
                    address = get_proc_address(hmod, import_name.encode())
                    if not ctypes.memmove(
                        func_ref_addr, address.to_bytes(ctypes.sizeof(LONG_PTR), 'little'), ctypes.sizeof(LONG_PTR)
                    ):
                        raise WindowsError('ctypes.memmove failed')
                if not bool(address):
                    raise WindowsError('Could not locate function for thunkref %s', import_name)
                func_ref_addr += ctypes.sizeof(PFARPROC)
                j += 1
            i += 1

    def free_library(self):
        if not bool(self.python_memory_module):
            return
        pmodule = ctypes.pointer(self.python_memory_module)
        if self.python_memory_module.contents.initialized != 0:
            dll_entry = DllEntryProc(
                self.python_memory_module.contents.codeBase
                + self.python_memory_module.contents.headers.contents.OptionalHeader.AddressOfEntryPoint
            )
            dll_entry(
                ctypes.cast(self.python_memory_module.contents.codeBase, wintypes.HINSTANCE),
                DLL_PROCESS_DETACH,
                0,
            )
            pmodule.contents.initialized = 0
        if bool(self.python_memory_module.contents.modules) and self.python_memory_module.contents.numModules > 0:
            for i in range(1, self.python_memory_module.contents.numModules):
                if self.python_memory_module.contents.modules[i] != wintypes.HANDLE(INVALID_HANDLE_VALUE):
                    FreeLibrary(self.python_memory_module.contents.modules[i])
        if bool(self._codebase_addr):
            VirtualFree(self._codebase_addr, 0, MEM_RELEASE)
        HeapFree(GetProcessHeap(), 0, self.python_memory_module)
        self.close()

    def free_exe(self):
        if not bool(self.python_memory_module):
            return
        pmodule = ctypes.pointer(self.python_memory_module)
        if bool(self._codebase_addr):
            VirtualFree(self._codebase_addr, 0, MEM_RELEASE)
        HeapFree(GetProcessHeap(), 0, self.python_memory_module)
        self.close()

    def _proc_addr_by_ordinal(self, idx):
        codebase = self._codebase_addr
        if idx == -1:
            raise WindowsError('Could not find the function specified')
        elif idx > self._exports_.NumberOfFunctions:
            raise WindowsError('Ordinal number higher than our actual count.')
        func_offset = wintypes.DWORD.from_address(codebase + self._exports_.AddressOfFunctions + (idx * 4))
        return func_offset.value

    def _proc_addr_by_name(self, name):
        codebase = self._codebase_addr
        exports = self._exports_
        if exports.NumberOfNames == 0:
            raise WindowsError("DLL doesn't export anything.")
        ordinal = -1
        name = name.lower()
        name_ref_addr = codebase + exports.AddressOfNames
        ordinal_addr = codebase + exports.AddressOfNamesOrdinals
        i = 0
        while i < exports.NumberOfNames:
            name_ref = wintypes.DWORD.from_address(name_ref_addr)
            func_name = ctypes.string_at(codebase + name_ref.value).lower()
            if func_name.decode() == name:
                ordinal = wintypes.WORD.from_address(ordinal_addr).value
            i += 1
            name_ref_addr += ctypes.sizeof(wintypes.DWORD)
            ordinal_addr += ctypes.sizeof(wintypes.WORD)
        return self._proc_addr_by_ordinal(ordinal)

    def get_proc_addr(self, name_or_ordinal):
        codebase = self._codebase_addr
        if not hasattr(self, '_exports_'):
            directory = self.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_EXPORT]
            if directory.Size <= 0:
                raise WindowsError('No export table found.')
            self._exports_ = IMAGE_EXPORT_DIRECTORY.from_address(codebase + directory.VirtualAddress)
            if self._exports_.NumberOfFunctions == 0:
                raise WindowsError("DLL doesn't export anything.")
        if isinstance(name_or_ordinal, str):
            procaddr_func = self._proc_addr_by_name
        elif isinstance(name_or_ordinal, int):
            procaddr_func = self._proc_addr_by_ordinal
        else:
            raise TypeError("Don't know what to do with name/ordinal of type: %s!" % type(name_or_ordinal))
        if name_or_ordinal not in self._foffsets_:
            self._foffsets_[name_or_ordinal] = procaddr_func(name_or_ordinal)
        return FARPROC(codebase + self._foffsets_[name_or_ordinal])

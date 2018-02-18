import idc
import idaapi
import idautils
from AutoAnalysis import definitions


# Init plugin
class autoAnalysis_t(idaapi.plugin_t):
	flags = 0
	comment = "AutoAnalysis Plugin"
	help = " "
	wanted_name = "AutoAnalysis"
	wanted_hotkey = "Ctrl-Alt-Y"

	def init(self):
		idaapi.autoWait() #Don't try and parse functions before IDA finishes initial analysis
		self.rename = True
		self.arch = idaapi.get_file_type_name()
		self.functionParse()
		self.rename = False
		return idaapi.PLUGIN_KEEP

	def run(self, arg):
		self.functionParse()
		pass


	def term(self):
		pass

	def functionParse(self):
		print "+++++ Auto Analyis ++++++"
		print "      Starting           "
		print "+++++++++++++++++++++++++"

		# Parse each functions // Skip library calls 
		for segea in idautils.Segments():
			for funcea in idautils.Functions(segea, SegEnd(segea)):
				functionName = idc.GetFunctionName(funcea)
				functionFlags = idc.GetFunctionFlags(funcea)
				if (functionFlags & idaapi.FUNC_LIB or
					functionFlags & idaapi.FUNC_THUNK or
					functionFlags & idaapi.FUNC_HIDDEN or
					functionFlags & idaapi.FUNC_STATICDEF):
					continue
				self.analyzeFunction(funcea)

	def analyzeFunction(self, funcea):
		# https://reverseengineering.stackexchange.com/questions/9352/finding-all-api-calls-in-a-function
		# Copy + Paste from Stack Overflow - Lika Boss
		n_flags = set() 
		dism_addr = list(idautils.FuncItems(funcea))
		for instr in dism_addr:
			tmp_api_address = ""
			if idaapi.is_call_insn(instr):
				for xref in idautils.XrefsFrom(instr, idaapi.XREF_FAR):
					if xref.to == None:
						continue
					tmp_api_address = xref.to
					break
				# get next instr since api address could not be found
				if tmp_api_address == "":
					continue
				api_flags = idc.GetFunctionFlags(tmp_api_address)
	
				# check for lib code (api)
				if (api_flags & idaapi.FUNC_LIB and api_flags & idaapi.FUNC_STATICDEF):
					tmp_api_name = idc.NameEx(0, tmp_api_address)
					if tmp_api_name:
						t_flags = self.processFunction( funcea, tmp_api_name)
						n_flags = ( t_flags| n_flags )
		# Rename function if flags populated
		# 	Skip of this isn't the first run
		if len(n_flags) > 0 and self.rename:
			fn = idc.GetFunctionName(funcea)
			sflags = "".join(set(n_flags))
			if not fn.startswith(sflags):
				print "Renaming - ", fn, " with - ", sflags
				idc.MakeName(funcea, str(sflags + "_" + fn ))

	def processFunction(self, funcea, apiName):
		t_flags = set()
		if self.arch.startswith('Portable executable'):

			## PEAPIS: PE - APIs function dictionary 
			for fType in definitions.PEAPIs.keys():
				if apiName.endswith("W"):
					apiName = apiName[:-1]
				if apiName in definitions.PEAPIs[fType]['calls']:
					print "[+] ",idc.GetFunctionName(funcea), " - Call: ", apiName, " --", fType
					t_flags.add(definitions.PEAPIs[fType]['flag'])
			return t_flags
		# This is where the else statement goes for other archs

		print apiName
		return set()



def PLUGIN_ENTRY():
	try:
		return autoAnalysis_t()
	except Exception, e:
		idaapi.msg("Failed to load AutoAnalysis")
		idaapi.msg(e)
		return idaapi.PLUGIN_SKIP

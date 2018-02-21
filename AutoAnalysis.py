import idc
import idaapi
import idautils
from idaapi import PluginForm
from PyQt5 import QtCore, QtGui

from AutoAnalysis import definitions

data = []

class AutoAnalysisOutput(PluginForm):
	#Based on code found @https://pastebin.com/raw/nMdTre1F
	def OnCreate(self, form):
		self.parent = self.FormToPyQtWidget(form)
		self.PopulateForm()

	def PopulateForm(self):
		layout = QtWidgets.QVBoxLayout()

		self.table = QtWidgets.QTableWidget()
		layout.addWidget(self.table)

		self.table.setColumnCount(3 + len(definitions.PEAPIs.keys()))

		self.table.setColumnWidth(0, 100)
		self.table.setHorizontalHeaderItem(0, QtWidgets.QTableWidgetItem("Address"))

		self.table.setColumnWidth(1, 250)
		self.table.setHorizontalHeaderItem(1, QtWidgets.QTableWidgetItem("Funciton"))

		self.table.setColumnWidth(2, 2)
		self.table.setHorizontalHeaderItem(2, QtWidgets.QTableWidgetItem(""))

		for index, name in enumerate(definitions.PEAPIs.keys()):

			self.table.setColumnWidth(3 + index, len(name)*10)
			self.table.setHorizontalHeaderItem(3 + index, QtWidgets.QTableWidgetItem(name))

		self.table.cellDoubleClicked.connect(self.double_clicked)

		self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
		self.parent.setLayout(layout)

		self.fill_table()

	def fill_table(self):
		self.table.setRowCount(len(data))

		row = 0
		for titem in data:
			

			item = QtWidgets.QTableWidgetItem('0x%X' % titem[0])
			item.setFlags(item.flags() ^ QtCore.Qt.ItemIsEditable)
			self.table.setItem(row, 0, item)

			item = QtWidgets.QTableWidgetItem(titem[1])
			item.setFlags(item.flags() ^ QtCore.Qt.ItemIsEditable)
			self.table.setItem(row, 1, item)

			item = QtWidgets.QTableWidgetItem(titem[2])
			self.table.setItem(row, 2, item)

			for col in range(0, len(definitions.PEAPIs.keys()) ):
				item = QtWidgets.QTableWidgetItem(titem[3 + col])
				self.table.setItem(row, 2 + col, item)

			row += 1

		self.table.resizeRowsToContents()

	def double_clicked(self, row, column):
		if column == 2:
			return
		
		idc.Jump(data[row][0])


	def OnClose(self, form):
		"""
		Called when the plugin form is closed
		"""
		pass

	def Show(self):
		return PluginForm.Show(self, "AutoAnalysis")



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
		ui = AutoAnalysisOutput()
		ui.Show()
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
		sflags = "".join(set(n_flags))
		if len(n_flags) > 0 and self.rename:
			fn = idc.GetFunctionName(funcea)
			if not fn.startswith(sflags):
				print "Renaming - ", fn, " with - ", sflags
				idc.MakeName(funcea, str(sflags + "_" + fn ))
		tbl = [ funcea, idc.GetFunctionName(funcea), sflags ]
		for f in definitions.PEAPIs.keys():
			if definitions.PEAPIs[f]['flag'] in sflags:
				tbl.append('*')
			else:
				tbl.append('')

		data.append( tbl )

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

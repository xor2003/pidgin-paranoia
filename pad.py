#!/usr/bin/python
# -*- coding: utf-8 -*-

#
#    One-Time pad Prototype - Encrypts your messages with a one-time pad. Can create inversed keys.
#    Copyright (C) 2007  Christian Wäckerlin
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.


import base64
import os
import sys
import mmap

class Pad:
	"""The onetimepad-class takes care of loading the entropy-file and xor-ing."""
	def __init__(self,instance):
		"""Remember the entropy-file."""
		self.instance=instance
		self.entropyfile=instance+'.entropy'
		self.size=os.path.getsize(self.entropyfile)
		self.error='\n'
		self.debug='\n'
		self.zerochar='\0'
		
	def __openfile(self):
		"""Opens the entropy-file."""
		self.file = file(self.entropyfile,'r+')
		self.data = data = mmap.mmap(self.file.fileno(), self.size)
		
	def __loadPosOLD(self):
		"""Gets the Position of the xor-ing pointer by taking the first byte not newline."""
	 	self.data.seek(0)
		while True:
			line=self.data.readline()
			if len(line) == 0:
				break
			if line <> '\n':
				break
		self.n=self.data.tell()-len(line)
		
	def __loadPos(self):
		"""Gets the Position of the xor-ing pointer by taking the first byte not newline."""
		p=0
		self.data.seek(0)
		while True:
			if self.data.read(1000) == self.zerochar*1000:
				p+=100
			else:
				self.data.seek(p)
				break
		while True:	
			if self.data.read(1) == self.zerochar:
				p+=1
			else:
				break
		self.n=p
		self.freeentropy=int(self.size/2)-self.n
		#self.freeentropy=int(720)-self.n	
		self.debug+= 'Free Entropy: '+str(self.freeentropy)+'\n'
		self.debug+= 'Position loaded: '+str(self.n)+'\n'
		
	def __savePos(self,pos,len):
		"""Saves the Position of the xor-ing pointer by overwriting entopy with newline."""
		self.data.seek(pos)
		string=self.zerochar*len
		self.data.write(string)
		self.debug+= 'Position saved: '+str(self.n+len)+'\n'
		
		
	def __closefile(self):
		"""Closes the entropy-file."""
		self.data.close()
		self.file.close()
		
	
		
	def encrypt(self,msg):
		"""Takes the message as argument and returns the crypted message. The entropy-file is read from the beginning.

A string of entropy with the length of the message is read from the file at the position of the xor-pointer and xored with the message.
The result is retured with the xor-pointer at the beginning and the new, increased xor-pointer is saved.
The crypted message is saved base64 encoded."""
		self.__openfile()
		self.__loadPos()
		self.freeentropy-=len(msg)
		key=''
		res=''
		if self.freeentropy>0:
			self.debug+= 'Message: '+msg+'\n'
			self.data.seek(self.n)
			key = self.data.read(len(msg))
			self.debug+= 'Key: '+key+'\n'
			res=self.__Xor(msg,key)
			self.debug+= 'Encrypted: '+res+'\n'
			res=self.base64encode(res)
			res=str(self.n)+'|'+res   #Put the xor-pointer in front of the payload.
		else:
			self.error+= 'You are out of entropy!'+'\n'
		self.__savePos(self.n,len(key))   
		self.__closefile()
		return res
		
		
		
	def decrypt(self,msg):
		"""Takes the cryped message and returns the message. The entropy-file is read from the end.

The crypted message is decoded from the base64-encoded transport-form.
The xor-position is read from the crypted message and the string of entropy is read from the end of the entropy-file and xored with the crypted message."""
		self.__openfile()
		spl=msg.split('|',1) 
		if len(spl) == 2:
			self.n = int(spl[0]) # Split the crypted message.
			msg=spl[1]
			self.debug+= 'Position of the message: '+str(self.n)+'\n'
			self.debug+= 'Encrypted: '+msg+'\n'
			if self.n >0:
				msg=self.base64decode(msg)
				self.data.seek(-self.n-len(msg),2)  # Goto the xor-pointer-position FROM THE END!
				key = self.data.read(len(msg))[::-1]  # Read the entropy-string and reverse it.
				res=self.__Xor(msg,key)
				self.debug+= 'Message: '+res+'\n'
				self.__closefile()
				return res
			else:
				return ''
				
		else:
			self.error+= '\nNot a valid onetimepad message.'
			return ''	
	
		
	def __Xor(self,str,key):
		"""Does the actual xoring."""
		result=''    
		for i in range(len(str)):
			result += chr(ord(str[i]) ^ ord(key[i]))  # XOR!
		return result
		
	def base64encode(self,str):
		"""Encode a string in base64."""
		return base64.b64encode(str)
		
	def base64decode(self,str):
		"""Decode a string from base64."""
		return base64.b64decode(str)
		

	
		
	
		
class Reverse:
   	"""This class takes care of the revering of the entropy-file."""
	def __init__(self,filein,fileout):
		"""Reverses the entropy file"""
		f = file(filein)
		g = file(fileout,'w')
		g.write(f.read()[::-1])
		f.close()
		g.close()
		
		
class CryptFrontend:
	"""A frontend for everything associated with the onetimepad."""
		
	def __init__(self):
		"""Does nothing here."""
		pass

	def encryptPrompt(self,instance):
		"""Encrypts the message with a given instance (entropy-file)."""
		if os.path.isfile(instance+'.entropy'):
			M = raw_input("Enter your message to encrypt:\n\n")
			print '\n'
			C=Pad(instance)
			res=C.encrypt(M)
			print 'Encrypted text:\n\n',res,'\n'
			print C.error
			#print C.debug
		else: 
			print 'File',instance+'.entropy does not exist.'
			
	def encrypt(self,instance,msg):
		"""Encrypts the message with a given instance (entropy-file)."""
		if os.path.isfile(instance+'.entropy'):
			M = msg
			C=Pad(instance)
			res=C.encrypt(M)
			return res
			print C.error
		else: 
			print 'File',instance+'.entropy does not exist.'
			
	def decrypt(self,instance,msg):
		"""Decrypts the message with a given instance (entropy-file)."""
		if os.path.isfile(instance+'.entropy'):
			M = msg
			C=Pad(instance)
			res=C.decrypt(M)
			return res
			print C.error
		else: 
			print 'File',instance+'.entropy does not exist.'		

	def decryptPrompt(self,instance):
		"""Decrypts the message with a given instance (entropy-file)."""
		if os.path.isfile(instance+'.entropy'):
			M = raw_input("Enter your message to decrypt:\n\n")
			print '\n'
			C=Pad(instance)
			res=C.decrypt(M)
			print 'Decrypted text:\n\n',res,'\n'
			print C.error
			#print C.debug
		else: 
			print 'File',instance+'.entropy does not exist.'

	def createPrompt(self,file1,file2):
		"""Creates an two 'entangled' entropy-files."""
		print 'FIXME\nUse \n\n dd if=/dev/urandom of=[INSTANCE].entropy bs=10M count=1 \n\n an then',sys.argv[0], 'reverse [INSTANCE]'

	def reversePrompt(self,instance1,instance2=''):
		"""Reverse an entropy-file to get the entangled one."""
		if os.path.isfile(instance1+'.entropy'):
			if instance2=='':
				instance2 = raw_input("Enter your the name of the target instance:\n\n")
			print '\n'
			Reverse(instance1+'.entropy',instance2+'.entropy')
			print 'Done.'
		else: 
			print 'File',instance+'.entropy does not exist.'
			
	def showProof(self):
		"""Print the proof for the security of onetimepads."""
		print "proof is a stub"		

class Main:
	"""The main-class."""
	def __init__(self):
		"""The main-funktion."""
		self.version='0.3'
		self.name='pad'
		self.prgname=sys.argv[0]
		#print len(sys.argv)
		Instance=CryptFrontend()
		done=0
		skip=0
		for i in range(1,len(sys.argv)):
			if skip<>0:
				skip-=1
			else:
				#print i
				if sys.argv[i]=='proof':
					Instance.showProof()
					done+=1
					
				if sys.argv[i]=='create' and len(sys.argv)>i+2:
					Instance.createPrompt(sys.argv[i+1],sys.argv[i+2])
					skip=2
					done+=1
					
				if sys.argv[i]=='reverse' and len(sys.argv)>i+2:
					Instance.reversePrompt(sys.argv[i+1],sys.argv[i+2])
					skip=2
					done+=1	
						
				if sys.argv[i]=='encrypt' and len(sys.argv)>i+1:
					Instance.encryptPrompt(sys.argv[i+1])
					skip=1
					done+=1
					
				if sys.argv[i]=='decrypt' and len(sys.argv)>i+1:
					Instance.decryptPrompt(sys.argv[i+1])
					skip=1
					done+=1		
					
				if sys.argv[i]=='encrypt-pipe' and len(sys.argv)>i+1:
					while True:
						line=sys.stdin.readline()
						if len(line)==0:
							break
						sys.stdout.writelines(Instance.encrypt(sys.argv[i+1],line)+'\n')
						sys.stdout.flush()
					skip=1
					done+=1
					
				if sys.argv[i]=='decrypt-pipe' and len(sys.argv)>i+1:
					while True:
						line=sys.stdin.readline()
						if len(line)==0:
							break
						sys.stdout.write(Instance.decrypt(sys.argv[i+1],line))
						sys.stdout.flush()
					skip=1
					done+=1					
		
		if done==0:
			self.usage()
			
			

				



	def usage(self):
		"""Print the usage-information for this program."""
		print self.name, 'Version:',self.version, '\n'
		print 'Usage:', self.prgname, '(encrypt|decrypt|create|reverse|proof)','INSTANCE','[pipe]'
		print 'A entropyfile named [INSTANCE].entropy is needed in the working directory.\n\n'
		print 'Ex.: Alice:', self.prgname, 'create Alice Bob'
		print "	Creates a pair of 'entangled' entropy-files."
		print	"	Alice keeps the one called bob.entropy and sends the one called alice.entropy to bob over a SECURE channel."
		print 'Ex.: Alice:',	self.prgname, 'encrypt bob' 
		print '	Encrypts the message to bob.'
		print 'Ex.: Bob:',self.prgname, 'decrypt alice'
		print '	Decrypts the message from alice.'



	

Main()







                
                




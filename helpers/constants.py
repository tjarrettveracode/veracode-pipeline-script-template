#constants.py - contains values related to Pipeline Scan capabilities

MAX_ANALYSIS_SIZE = 104857600 #100mb

# Java, JavaScript, Typescript, Kotlin, Scala, Groovy, .NET
SUPPORTED_COMPILERS = ["JAVAC_1_4","JAVAC_5","JAVAC_6","JAVAC_7","JAVAC_8",\
    "MSIL_MSVC6","MSIL_MSVC8_X86","MSIL_MSVC8_X86_64","MSIL_MSVC11_X86","MSIL_MSVC11_X86_64",\
        "MSIL_MSVC14_X86","MSIL_MSVC14_X86_64",\
        "JAVASCRIPT_5_1"] 
SUPPORTED_ARCH = ["JVM", "CIL32","CIL64","JAVASCRIPT"]

SEVERITIES = { "5" : "Very High", "4": "High", "3": "Medium", "2": "Low", "1": "Very Low", "0": "Informational"}

#compiler="JAVAC_5" os="Java J2SE 6" architecture="JVM"
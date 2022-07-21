import numpy as np
from mceliece import McEliece
from aux_functions import GF2
import csv

''' Ficheros '''
inputData = "DB//data.csv"
inputInscripcion = "DB//ejemploInscripcion.csv"
inputIdVer = "DB//ejemploInput.csv"
databaseFile = "DB//db.dat"
auxDatabaseFile = "DB//auxdb.dat"
errorsFile = "DB//errors.dat"
publicKeyFile = "DB//pubkey.npy"

templatesPerUser = 10

''' Parámetros McEliece '''
#m = 4   
#n = 12  
#t = 2  
# k = 4 
m = 12
n = 2960
t = 56
# k = 2288

''' Umbral de comparación 0 <= threshold <= 1 '''
thresholdDefault = 1

''' Separar patrón en el numero de bloques correspondiente y añadir padding '''
def splitAndPad(row, k):
    blocks = int(np.ceil(len(row) / k))
    row = [int(elem) for elem in row]
    # Separar fila en bloques de k bits (saltándose el primer elemento)
    splitted = [row[i * k + 1 : (i + 1) * k + 1] for i in range(blocks)]
    # Añadir padding al último elemento
    while len(splitted[-1]) < k:
        splitted[-1] += [0]
    return splitted, blocks, row[0]

''' Escribir array en un fichero '''
def writeArray(array, file, csv):
    for elem in array.tolist():
        if csv:
            file.write(str(elem) + ',')
        else:
            file.write(str(elem))
        
''' Cifrar con un vector de error predeterminado '''
def mceencrypt(message, SGP, errlines, index):
    # Encontrar el error correspondiente en el fichero
    error = []
    for bit in errlines[index]:
        if bit != '\n': error += [bit]
    #ciphertext = GF2(message).dot(GF2(SGP)) + GF2(error)
    ciphertext = np.array(message).dot(np.array(SGP)) + np.array([int(x) for x in error])
    return ciphertext, error
   
''' Cifrar el patron de consulta una vez dividido en bloques y utilizando el vector de errores correspondiente para cada bloque '''
def cipherInputTemplate(splitted, SGP, errlines, i, blocks):
    inputTemplate = []
    d = 0
    for block in splitted:
        errorIndex = i *  blocks + d
        ciphertext, _ = mceencrypt(block, SGP, errlines, errorIndex)
        for bit in ciphertext.tolist():
            inputTemplate += [bit]
        d += 1     
    return inputTemplate

''' Encontrar el índice de la fila correspondiente a un id de usuario '''
def findIndex(auxdblines, userid):
    found = False
    i = 0
    for row in auxdblines:
        if int(row) == userid:
            found = True
            break
        i += 1
    return i, found

''' Comparar dos strings en función de un cierto umbral '''
def comparator(inputTemplate, cipherTemplate, threshold):
    if len(inputTemplate) != len(cipherTemplate):
        return False
    cipherTemplate = [int(x) for x in cipherTemplate]
    euclidDistance = np.linalg.norm(np.array(inputTemplate)-np.array(cipherTemplate))
    return euclidDistance <= threshold, euclidDistance


''' Fase de Inscripción '''
def enrollment(inputFile, databaseFile, auxDatabaseFile, errorsFile, publicKeyFile):
    # Generar McEliece (128 bits seguridad) 
    mce = McEliece(m, n, t) 
    (SGP, _), _ = mce.keyGen()
    # Mensajes de k bits
    k = mce.goppaCode.k
    
    with open(inputFile, 'r', newline='') as infile, open(databaseFile, 'w', newline='') as dbfile, open(auxDatabaseFile, 'w', newline='') as auxdbfile, open(errorsFile, 'w', newline='') as errfile:
        infileReader = csv.reader(infile, delimiter=',')
        # Un patrón por cada 10 filas
        i = 0
        for template in infileReader:
            if i % templatesPerUser == 0 :
                # Separar en bloques el patrón
                splitted, _, userid = splitAndPad(template, k)
                # Escribir el id del usuario en la base de datos auxiliar
                auxdbfile.write(str(userid) + '\n')
                print(f"UserID: {userid}")
                for block in splitted:
                    # Cifrar cada bloque y guardar el vector de errores de cada cifrado 
                    ciphertext, error = mce.encrypt(block)
                    writeArray(ciphertext, dbfile, True)
                    writeArray(error, errfile, False)
                    errfile.write('\n')
                dbfile.write('\n')
            i += 1

    # Guardar matriz SGP
    np.save(publicKeyFile, SGP)
    return mce


''' Fase de Identificación '''
def identification(inputFile, databaseFile, auxDatabaseFile, errorsFile, publicKeyFile, threshold=-1):
    # Recuperar la clave pública (matriz de cifrado)
    SGP = np.load(publicKeyFile)
    k = SGP.shape[0]
    
    with open(inputFile, 'r', newline='') as infile, open(databaseFile, 'r', newline='') as dbfile, open(auxDatabaseFile, 'r', newline='') as auxdbfile, open(errorsFile, 'r', newline='') as errfile:
        # Coger el dato biometrico de inputFile y separarlo en bloques
        infileReader = csv.reader(infile, delimiter=',')
        template = next(infileReader)
        splitted, blocks, _ = splitAndPad(template, k)
        
        errlines = errfile.read().splitlines()
        auxdblines = auxdbfile.read().splitlines()
        dbReader = csv.reader(dbfile, delimiter=',')
        dblines = list(dbReader)

        # Iterar por cada fila de patrones cifrados
        i = 0
        minimum = 0
        for cipherTemplate in dblines: 
            # Construir el cifrado del patrón introducido y comparar
            inputTemplate = cipherInputTemplate(splitted, SGP, errlines, i, blocks)
            _, dist = comparator(inputTemplate, cipherTemplate[0:-1], threshold)
            # Almacenar si es el mas parecido
            if dist < minimum or i == 0:
                minimum = dist
                retAuxdblines = auxdblines[i]
                retCipherTemplate = cipherTemplate
            i += 1
        return retAuxdblines, retCipherTemplate, minimum
    
    
''' Fase de Verificación '''
def verification(inputFile, databaseFile, auxDatabaseFile, errorsFile, publicKeyFile, threshold):
    # Recuperar la clave pública (matriz de cifrado)
    SGP = np.load(publicKeyFile)
    k = SGP.shape[0]
    
    with open(inputFile, 'r', newline='') as infile, open(databaseFile, 'r', newline='') as dbfile, open(auxDatabaseFile, 'r', newline='') as auxdbfile, open(errorsFile, 'r', newline='') as errfile:
        # Coger el dato biometrico de inputFile y separarlo en bloques
        infileReader = csv.reader(infile, delimiter=',')
        template = next(infileReader)
        splitted, blocks, userid = splitAndPad(template, k)
        
        errlines = errfile.read().splitlines()
        auxdblines = auxdbfile.read().splitlines()
        dbReader = csv.reader(dbfile, delimiter=',')
        dblines = list(dbReader)
        
        # Índice de la fila en la base de datos auxiliar
        i, found = findIndex(auxdblines, userid)
        if not found: 
            print("No está ese usuario en la base de datos"); 
            return False
        
        # Coger el patrón cifrado de la fila correspondiente
        cipherTemplate = dblines[i]
        
        # Construir el cifrado del patrón introducido y comparar
        inputTemplate = cipherInputTemplate(splitted, SGP, errlines, i, blocks)
        comp, _ = comparator(inputTemplate, cipherTemplate[0:-1], threshold)
        return auxdblines[i], cipherTemplate, comp

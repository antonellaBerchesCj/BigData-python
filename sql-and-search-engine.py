import sys
import sqlite3 as lite	
	
def printMatrixA():
	print 'Matrice A:'
	con = lite.connect('matrix.db')
	cursor = con.cursor() #get a cursor object
	cursor = con.execute('SELECT row_num, col_num FROM a order by row_num desc')
	
	firstRow = cursor.fetchone() #fetchone() retrieves the next row of a query result set and returns a single sequence
	
	#creare matrice. Pune 0 peste tot
	matrixA = [[0 for x in range(firstRow[0] + 1)] for y in range(firstRow[1] + 1)] 
	
	#preluare date din BD pt aconstrui matricea
	cursor.execute('SELECT row_num as row, col_num as col, value FROM a')

	#get all rows from table
	rows_table = cursor.fetchall()
	
	for row in rows_table:
		matrixA[row[0]][row[1]] = row[2]

	con.close()
	
	if matrixA is not '':
		for row in matrixA:
			print row
	return matrixA
	
def printMatrixB():
	print '\nMatrice B:'
	con = lite.connect('matrix.db')
	cursor = con.cursor() #get a cursor object
	cursor = con.execute('SELECT row_num, col_num FROM b order by row_num desc')
	
	firstRow = cursor.fetchone()#fetchone() retrieves the next row of a query result set and returns a single sequence
	
	#creare matrice. Pune 0 peste tot
	matrixB = [[0 for x in range(firstRow[0] + 1)] for y in range(firstRow[1] + 1)] 
	
	#preluare date din BD pt aconstrui matricea
	cursor.execute('SELECT row_num as row, col_num as col, value FROM b')

	#get all rows from table
	rows_table = cursor.fetchall()
	
	for row in rows_table:
		matrixB[row[0]][row[1]] = row[2]

	con.close()
	
	if matrixB is not '':
		for row in matrixB:
			print row
	return matrixB

def inmultireAB():
	matriceA = printMatrixA()
	matriceB = printMatrixB()
	zip_matB = zip(*matriceB) #zip() in conjunction with the * operator can be used to unzip a list
	inmultire = [[sum(A * B for A, B in zip(row_A, col_B))
	for col_B in zip_matB] for row_A in matriceA]

	print ("\nInmultire matrice (AxB):")
	for row in inmultire:
		print row

def main():
	#printMatrixA()
	#printMatrixB()
	inmultireAB()
	
if __name__ == '__main__':
	main()
	

	

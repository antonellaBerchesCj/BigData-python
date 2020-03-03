#!/usr/bin/env python
'''
Author: Berches Antonela

Laborator 10: Algoritmul PageRank

'''

import networkx as nx
import matplotlib.pyplot as plt
import scipy as sp
import numpy as np


iteration, error = 0, 1
previous_matrix = []

g = nx.Graph()

# Add a node n and update node attributes.
g.add_node(1), g.add_node(2), g.add_node(3), g.add_node(4), g.add_node(5), 
g.add_node(6), g.add_node(7), g.add_node(8), g.add_node(9), g.add_node(10)

# Add an edge between u and v. --> g.add_edge(u, v)
g.add_edge(1,2), g.add_edge(1,3), g.add_edge(2,4), g.add_edge(2,6), g.add_edge(3,1)
g.add_edge(3,2), g.add_edge(3,4), g.add_edge(4,3), g.add_edge(4,5), g.add_edge(5,6)
g.add_edge(5,7), g.add_edge(5,8), g.add_edge(6,2), g.add_edge(6,7), g.add_edge(7,5)
g.add_edge(7,8), g.add_edge(8, 4), g.add_edge(8,9), g.add_edge(8,10), g.add_edge(9,7)
g.add_edge(9,10), g.add_edge(10,8)       


transition_matrix =  [[0,     0,      0.55,  0,    0,    0,   0.5,  0,    0,   0 ],
					  [0.5,   0,      0.55,  0,    0,    0.5, 0,    0,    0,   0 ],
					  [0.5,   0,      0,     0.5,  0,    0,   0,    0,    0,   0 ],
					  [0,     0.5,    0.55,  0,    0,    0,   0,    0.55, 0,   0 ],
					  [0,     0,      0,     0.5,  0,    0,   0.5,  0,    0,   0 ],
					  [0,     0.5,    0,     0,    0.55, 0,   0,    0,    0,   0 ],
					  [0,     0,      0,     0,    0.55, 0.5, 0,    0,    0.5, 0 ],
					  [0,     0,      0,     0,    0.55, 0,   0.5,  0,    0,   1 ],
					  [0,     0,      0,     0,    0,    0,   0,    0.55, 0,   0 ],
					  [0,     0,      0,     0,    0,    0,   0,    0.55, 0.5, 0]]

# vector_v0 se va actualiza prin inmultiri repetate cu matricea		  
vector_v0 = [[0.1],
	         [0.1],
	         [0.1],
			 [0.1],
			 [0.1],
			 [0.1],
			 [0.1],
			 [0.1],
			 [0.1], 
			 [0.1]]
		 
def multiply_matr(matrice1, matrice2):
	res, mat_mul = [], []

	for i in range(len(matrice1)):
		for j in range(len(matrice2[0])):
			suma = 0
			for k in range(len(matrice2)):
				suma = suma + (matrice1[i][k]*matrice2[k][j])
			res.append(suma)
		mat_mul.append(res)
		res = []
	# print(mat_mul)
	return mat_mul
	
	
def compare(a, b):
	for i in range(len(a)):
		result = np.fabs(a[i][0] - b[i][0])
		if (result < error):
			return False
	return True

previous_matrix = vector_v0

# iterate through nodes
for i in range (1, 10):
	result = multiply_matr(transition_matrix, previous_matrix)
	iteration = iteration + 1
	
	if compare(result, previous_matrix):
		break
	print(result)
	previous_matrix = result
	
plt.title('Numar de iteratii: %d' % iteration)
nx.draw(g)
plt.show()

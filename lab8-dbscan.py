#!/usr/bin/env python
'''
Author: Berches Antonela

Laborator 8: Tehnici de clustering

DBSCAN clustering algorithm (Density-Based Spatial Clustering of Applications with Noise)

'''

import numpy as np
from PIL import Image
import matplotlib.pyplot as plt
from sklearn.cluster import DBSCAN
from sklearn.datasets.samples_generator import make_blobs
from sklearn.preprocessing import StandardScaler
from sklearn import metrics


def get_pixels(img):
    '''
    Get image pixels
    '''
    pixels = []
    for h in range(img.size[1]):
		for w in range(img.size[0]):
			if (img.getpixel((w, h))==0):
				pixels.append([w, h])
    return pixels
		

img = 'dataset/circles.png'
im = Image.open(img)

# standardize features by removing the mean and scaling to unit variance
X = StandardScaler().fit_transform(get_pixels(im)) # fit to data, then transform it.
print (X)
np.savetxt('dataset_circles.txt', X)


# Compute DBSCAN
db = DBSCAN(eps=0.09, min_samples=10).fit(X)
'''
eps: the maximum distance between two samples for them to be considered as in the same neighborhood.
min_samples: the number of samples (or total weight) in a neighborhood for a point to be considered as a core point. This includes the point itself.
'''

core_samples_mask = np.zeros_like(db.labels_, dtype=bool)
core_samples_mask[db.core_sample_indices_] = True
labels = db.labels_

# Number of clusters in labels, ignoring noise if present
nr_clusters = len(set(labels)) - (1 if -1 in labels else 0)
print('Estimated number of clusters: %d' % nr_clusters)

# plot results
# black removed and is used for noise instead.
unique_labels = set(labels)
colors = plt.cm.Spectral(np.linspace(0, 1, len(unique_labels))) # return evenly spaced numbers over a specified interval.
for k, col in zip(unique_labels, colors):
    if k == -1:
        col = 'k' # # Black used for noise.
        # col = [0, 0, 0, 1]

    class_member_mask = (labels == k)
    
    # https://matplotlib.org/api/_as_gen/matplotlib.axes.Axes.plot.html
    xy = X[class_member_mask & core_samples_mask]
    plt.plot(xy[:, 0], xy[:, 1], 'o', markerfacecolor=col, markeredgecolor='k', markersize=14)

    xy = X[class_member_mask & ~core_samples_mask]
    plt.plot(xy[:, 0], xy[:, 1], 'o', markerfacecolor=col, markeredgecolor='k', markersize=6)

plt.title('Numar de clustere: %d' % nr_clusters)
plt.show()

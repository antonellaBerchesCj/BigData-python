#!/usr/bin/env python
'''
Author: Berches Antonela

Laborator 8: Tehnici de clustering

K-MEANS clustering algorithm

'''

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from PIL import Image
from sklearn.preprocessing import StandardScaler

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

def png_to_dataset():
    '''
    Get image dataset
    '''
    img = 'dataset/circles.png'
    im = Image.open(img)

    # standardize features by removing the mean and scaling to unit variance
    X = StandardScaler().fit_transform(get_pixels(im)) # fit to data, then transform it.
    print (X)
    np.savetxt('dataset.txt', X)


def load_dataset(name):
    '''
    Load textfile dataset
    '''
    return np.loadtxt(name)


def euclidian(a, b):
    '''
    Euclidian distance between 2 data points
    '''
    return np.linalg.norm(a-b)


def draw_window(dataset, old_centroids, belongs_to):
    '''
    define plotting algorithm for our dataset amd centroids
    '''
    colors = ['r', 'g'] # define 2 colors for each centroid cluster
    fig, axis = plt.subplots() # split our graph by its axis and actual plot

    # for each point in our dataset
    for index in range(dataset.shape[0]):
        # get all the points assigned to a cluster
        instances_close = [i for i in range(len(belongs_to)) if belongs_to[i] == index]

        # assign each datapoint in that cluster a color and plot it
        for instance_index in instances_close:
            axis.plot(dataset[instance_index][0], dataset[instance_index][1], (colors[index] + 'o'))

    # log the history of centroids calculated via training
    history_points = []

    # for each centroid ever calculated
    for index, centroids in enumerate(old_centroids):
        for i, item in enumerate(centroids):
            if index == 0:
                history_points.append(axis.plot(item[0], item[1], 'bo')[0])
            else:
                history_points[i].set_data(item[0], item[1])
                print('\ncentroids {} {}'.format(index, item))

                # plt.show()
                plt.title('K-MEANS clustering algoithm:')
                plt.pause(0.8)



def kmeans(k, epsilon=0, distance='euclidian'):
    '''
    Given k , the K-means algorithm works as follows:
    1. Randomly choose k data points (seeds) to be the initial centroids
    2. Assign each data point to the closest centroid
    3. Re-compute (update) the centroids using the current cluster memberships
    4. If a convergence criterion is not met, go to step 2

    k: nr of clusters
    epsilon: minimum error to use in the stop condition
    distance: euclidan distance

    return: 
        calculated centroids
        history of them all
        assignments for which cluster each datapoint belongs to
    '''

    old_centroids = []
    if distance == 'euclidian':
        dist_method = euclidian
    dataset = load_dataset('dataset.txt')
    # dataset = dataset[:, 0:dataset.shape[1] - 1]

    num_rows, num_cols = dataset.shape # get rows, cols from dataset

    # define how many clusters to find (k centroids) and chose randomly
    clusters = dataset[np.random.randint(0, num_rows - 1, size=k)]

    # set these to our list of past centroid (to show progress over time)
    old_centroids.append(clusters)

    # to keep track of centroid at every iteration
    clusters_old = np.zeros(clusters.shape)

    belongs_to = np.zeros((num_rows, 1)) # store clusters - return a new array of given shape, filled with zeros.
    norm = dist_method(clusters, clusters_old)
    iteration = 0
    
    while norm > epsilon:
        iteration += 1
        norm = dist_method(clusters, clusters_old)
        clusters_old = clusters

        # for each instance in the dataset
        for index_instance, instance in enumerate(dataset):
            dist_vec = np.zeros((k, 1)) # define a distance vector of size k

            # for each centroid
            for index_centroid, centroid in enumerate(clusters):
                # compute the distance between x and centroid
                dist_vec[index_centroid] = dist_method(centroid, instance)

            # find the smallest distance, assign that distance to a cluster
            belongs_to[index_instance, 0] = np.argmin(dist_vec)

        tmp_clusters = np.zeros((k, num_cols))

        # for each cluster (k of them)
        for index in range(len(clusters)):
            # get all the points assigned to a cluster
            instances_close = [i for i in range(len(belongs_to)) if belongs_to[i] == index]

            # this is our new centroid - compute the arithmetic mean along the specified axis.
            centroid = np.mean(dataset[instances_close], axis=0)
            tmp_clusters[index, :] = centroid # add our new centroid to our new temporary list

        clusters = tmp_clusters # set the new list to the current list
        old_centroids.append(tmp_clusters) #add our calculated centroids to our history for plotting

    draw_window(dataset, old_centroids, belongs_to)

    return clusters, old_centroids, belongs_to

def main():
    png_to_dataset()
    dataset = load_dataset('dataset.txt')
    
    centroids, old_centroids, belongs_to = kmeans(2)
    draw_window(dataset, old_centroids, belongs_to)

if __name__ == "__main__":
    main()

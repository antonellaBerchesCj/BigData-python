#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Author: Berches Antonela

Laborator 11: Regresie liniara (Simpla)

'''

import numpy as np
from PIL import Image
import matplotlib.pyplot as plt


def estimate_coefficients(x, y):
    '''
    To create our model, we must “learn” or estimate the values of regression 
    coefficients b_0 and b_1. And once we’ve estimated these coefficients, 
    we can use the model to predict responses.
    '''
    n = np.size(x) # number of observations/points
    mean_x_vector, mean_y_vector = np.mean(x), np.mean(y) # mean of x and y vector

    # determine cross-deviation and deviation about x
    sum_cross_deviations_deviation_xy = np.sum(y * x - n * mean_y_vector * mean_x_vector)
    sum_squared_deviation_xx = np.sum(x * x - n * mean_x_vector * mean_x_vector)

    # determine regression coefficients
    # b_0 and b_1 are regression coefficients and represent y-intercept and slope of regression line respectively
    b_1 = sum_cross_deviations_deviation_xy / sum_squared_deviation_xx
    b_0 = mean_y_vector - b_1 * mean_x_vector

    return(b_0, b_1)


def plot_regr_line(x, y, b):
    '''
    Plot regression line
    '''
    plt.style.use('fivethirtyeight')
    plt.scatter(x, y, color = 'b') # plotting the actual points as scatter plot
    y_pred = b[0] + b[1] * x # predicted response vector
    plt.plot(x, y_pred, color = 'r') # plotting the regression line
    plt.xlabel('x'); plt.ylabel('y')

    # plt.hlines(y = 0, xmin = 0, xmax = 50, linewidth = 2) # plotting line for zero residual error
    # setting plot style
    plt.title('Linear regression')
    plt.show()


def get_pixels(image):
    '''
    Get image pixels
    '''
    im = Image.open(image)
    pixels = list(im.getdata())
    width, height = im.size
    return [pixels[i * width:(i + 1) * width] for i in range(height)]


def get_coord(dataset):
    '''
    Extact image coordinates x, y
    '''
    x, y = list(), list()
    for row, row_data in enumerate(dataset):
        for col, pixel in enumerate(row_data):
            if pixel == (0, 0, 0):
                x.append(row)
                y.append(col)

    # print(x, y)
    return [x, y]


def main():
    file = 'dataset/one.jpg'
    x = np.array(get_coord(get_pixels(file))[0])
    y = np.array(get_coord(get_pixels(file))[1])

    b = estimate_coefficients(x, y)
    print('Estimated coefficients:\nb_0 = {} \nb_1 = {}'.format(b[0], b[1]))

    plot_regr_line(x, y, b)

if __name__ == '__main__':
    main()

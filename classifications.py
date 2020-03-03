#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Classifications
'''
import numpy as np
import matplotlib.pyplot as plt
from sklearn import svm
from sklearn.decomposition import PCA
from sklearn.datasets import load_digits
from sklearn.model_selection import learning_curve

digits = load_digits()
x, y = digits.data, digits.target
pca = PCA(5)
pca.fit(x)
x = pca.transform(x)
svc = svm.SVC(kernel='linear')
x_train, y_train = x[:int(len(x)*0.6)], y[:int(len(y)*0.6)]
x_valid, y_valid = x[len(x_train):], y[len(y_train):]
svc.fit(x_train, y_train)
y_predicted = svc.predict(x_valid)

ylim = None
plt.figure()
plt.title("Rezultate invatare liniara")
if ylim is not None:
    plt.ylim(*ylim)
    
plt.xlabel("Marime date de invatare")
plt.ylabel("Punctaj")
train_sizes, train_scores, test_scores = learning_curve(svc, x_train, y_train,  cv=5)
train_scores_mean = np.mean(train_scores, axis=1);train_scores_std = np.std(train_scores, axis=1)
test_scores_mean = np.mean(test_scores, axis=1);test_scores_std = np.std(test_scores, axis=1)
plt.grid()

plt.fill_between(train_sizes, train_scores_mean - train_scores_std, train_scores_mean + train_scores_std, alpha=0.1, color="r")
plt.fill_between(train_sizes, test_scores_mean - test_scores_std, test_scores_mean + test_scores_std, alpha=0.1, color="g")
plt.plot(train_sizes, train_scores_mean, 'o-', color="y", label="Curba de invatare")
plt.plot(train_sizes, test_scores_mean, 'o-', color="b", label="Curba de performanta")
plt.legend(loc="best")
plt.show()

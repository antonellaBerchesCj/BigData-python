#!/usr/bin/python

'''
Laborator 1: Analiza sentimentelor din tweet-uri

Autor: Antonella Berches

'''

import re
import os
import json
import operator

from collections import Counter
from statistics import median

def create_dict_scores():
    '''
    Create dictionary from sentiment_scores.txt file.
    '''
    dict_scores = {}

    with open('sentiment_scores.txt') as fin:
        dict_scores = dict(x.rstrip().split('\t') for x in fin)
    return dict_scores

# ex.1
def get_feeling_score(words_list, start_score):
    '''
    Parse each tweet and check if it exists in sentiment_scores.txt file.
    If exists, get its score and update tweet's score.
    '''
    score = {}
    score['words'] = [];
    feelingScore = 0
    score['feelingScore'] = 0;
    sentimentScores = create_dict_scores()

    for tweet in words_list:
        parsed_tweet = re.search(r'(^[a-zA-Z*\-a-zA-Z*]{3,}$)', tweet)
        if parsed_tweet:
            parsed_tweet = parsed_tweet.group().lower()
            
            if start_score == 2:
                score['words'].append(parsed_tweet)

            if tweet in sentimentScores:
                score['feelingScore'] += int(sentimentScores[parsed_tweet])
    return score
    
def get_feeling_from_tweet(start_score):
    '''
    Get feeling from each tweet starting from a point score.
    '''
    score = {}
    score['scores'] = []
    score['result'] = {}

    if start_score == 1:
        fin = open('tweets_score.txt', 'w')
    
    i = 0

    with open('twitter_data.txt','r',) as tw_file:    
        for line in tw_file:
            i += 1

            tweet = json.loads(line).get('text')
            parsed_tweet = re.sub('\s+', ' ', tweet.encode('utf-8'))
            feelingScore = get_feeling_score(parsed_tweet.split(' '), start_score)
            
            if start_score == 1:
                tweets = tweet.encode('utf-8')
                fin.write('Tweet ' + str(i) + ' - score: ' + str(feelingScore['feelingScore']) + '\n')
            elif start_score == 2:
                score['scores'].extend(feelingScore['words'])
            elif start_score == 3:
                score['result'].update({i:str(feelingScore['feelingScore'])})

    if start_score == 1:
        fin.close()

    return score

# ex.2
def top500_words():
    '''
    Get top 500 most common words from the tweet 
    '''
    all_words = get_feeling_from_tweet(2)
    count_dict = Counter(all_words['scores'])

    with open('top500.txt', 'a') as fin:
        fin.write(str(count_dict.most_common(500)))
    fin.close()
    
    return count_dict.most_common(500)

# ex.3
def missing_words(top500, all_scores):
    '''
    Create a dictionary with top 500 words that cannot be found in sentiment_scores.txt.
    '''
    missing_words_dic = {}

    for key in top500:
        word = key[0]
        if word not in all_scores:
            if word not in missing_words_dic:
                missing_words_dic.update({word:0})
    return missing_words_dic

def find_words_in_json():
    '''
    Find top 500 missing words from sentiment_scores.txt in the list and add in words dictionary.
    '''
    i = 0
    words = {}
    missing_dic = missing_words(top500_words(), create_dict_scores())

    with open('twitter_data.txt','r',) as tw_file:    
        for line in tw_file:
            i += 1

            tw_data = json.loads(line)
            tweet = tw_data.get('text')
            parse_tweet = re.sub('\s+', ' ', tweet.encode('utf-8'))
            words_list = parse_tweet.split(' ')

            for key in words_list:
                parsed_tweet = re.search(r'(^[a-zA-Z*\-a-zA-Z*]{3,}$)', key)
                if parsed_tweet:
                    my_list = []
                    parsed_tweet = parsed_tweet.group().lower()

                    if parsed_tweet in missing_dic:
                        if parsed_tweet in words:
                            my_list = words[parsed_tweet]
                            my_list.append(i)
                            words.update({parsed_tweet:my_list})
                        else:
                            my_list.append(i)
                            words.update({parsed_tweet:my_list})
    return words

def get_words_score(words):
    '''
    Loop missing_words dictionary and for each word check in which json is found.
    Then check the score for the word. If json result is positive, add 1, else decrese by 1 the score.
    '''
    json_info = get_feeling_from_tweet(3)['result']
    missing_dic = missing_words(top500_words(), create_dict_scores())

    for word in missing_dic:
        for json in words[word]:
            if int(json_info[json]) > 0 :
                missing_dic[word] += 1

            if int(json_info[json]) < 0 :
                missing_dic[word] -= 1

    with open('missing_words.txt', 'a') as fin:
        fin.write(str(missing_dic) + ' ' + str(len(missing_dic)))
    fin.close()

# ex.4
def friends_or_money():
    '''
    Get friends_count from each json and place it in positive/negative/neutre dictionary.
    Calculate median from each dictionary values.
    '''
    i = 0
    json_info = get_feeling_from_tweet(3)['result']
    pos_dic = {}
    neg_dic = {}
    neutr_dic = {}

    with open('twitter_data.txt','r',) as tw_file:    
        for line in tw_file:
            i += 1
            friends_count = json.loads(line).get('user').get('friends_count')

            if int(json_info[i]) > 0:
                pos_dic.update({str(i) : friends_count})
            elif int(json_info[i]) == 0:
                neg_dic.update({str(i) : friends_count})
            else:
                neutr_dic.update({str(i) : friends_count})

    filename = 'friends_or_money.txt'
    if os.path.exists(filename):
        os.remove(filename)

    with open(filename, 'a') as fin:
        fin.write('Positive: ' + str(median(pos_dic.values())))
        fin.write('\nNegative: ' + str(median(neg_dic.values())))
        fin.write('\nNeutre: ' + str(median(neutr_dic.values())))
    fin.close()


if __name__ == '__main__':
    get_feeling_from_tweet(1)
    print('Check tweets_score.txt file!')

    top500_words()
    print('Check top500.txt file!')

    get_words_score(find_words_in_json())
    print('Check missing_words.txt file!')

    friends_or_money()
    print('Check friends_or_money.txt file!')

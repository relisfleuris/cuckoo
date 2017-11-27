from sklearn.neighbors import KNeighborsClassifier
from cuckoo.common.abstracts import Learn

class KNN(Learn):

    def run(self, results):
        self.preparate_dataset()
        knn = KNeighborsClassifier(weights='distance')
        knn.fit(self.X, self.Y)
        data = self.get_data(results)
        if data is None:
            return
        prediction = cart.predict(data)
        score = cart.predict_proba(data)
        self.set_predict(results,prediction[0])
        self.set_score(results, score[0])
    def get_data(self, results):
        #first get all apis used in this artfact (20)
        api_list = self.parameters[:20]
        if 'behavior' in results:
            apistats = results["behavior"]["apistats"]
        else:
            return None
        report = []
        count = 0
        for a in api_list:
            for process, values in apistats.iteritems():
                for api, freq in values.iteritems():
                    if a in api:
                        count +=freq
            report.append(count)
            count = 0
        behavior = results["behavior"]
        try:
            dropped = results["dropped"]
        except:
            dropped = []
        report.append(len(behavior))
        report.append(len(dropped))
        try:
            hosts = results["network"]["hosts"]
        except:
            hosts = []
        try:
            avgentropy = round(self.entropy(results["static"]["pe_sections"]), 4)
        except:
            avgentropy = 5 #standard avg entropy
        report.append(len(hosts))
        report.append(avgentropy)
        answer = [] #needs a 2D array, to predict something
        print report
        answer.append(report)
        print answer
        return answer

from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from cuckoo.common.abstracts import Learn

class LDA(Learn):

    def run(self, results):
        self.preparate_dataset()
        lda = LinearDiscriminantAnalysis()
        lda.fit(self.X, self.Y)
        data = self.get_data(results)
        prediction = lda.predict(data)
        score = lda.predict_proba(data)
        self.set_predict(results,prediction[0])
        self.set_score(results, score[0])
    def get_data(self, results):
        #first get all apis used in this artfact (20)
        api_list = self.parameters[:20]
        apistats = results["behavior"]["apistats"]
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
        avgentropy = round(self.entropy(results["static"]["pe_sections"]), 4)
        report.append(len(hosts))
        report.append(avgentropy)
        answer = [] #needs a 2D array, to predict something
        answer.append(report)
        return answer

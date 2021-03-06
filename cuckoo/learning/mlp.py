from sklearn.neural_network import MLPClassifier
from cuckoo.common.abstracts import Learn
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline

class MLP(Learn):

    def run(self, results):
        self.preparate_dataset()
        mlp = make_pipeline(StandardScaler(),MLPClassifier(max_iter=200, alpha=0.001, solver='lbfgs', activation='tanh'))
        mlp.fit(self.X, self.Y)
        data = self.get_data(results)
        if data is None:
            return
        prediction = mlp.predict(data)
        score = mlp.predict_proba(data)
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

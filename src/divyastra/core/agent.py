class Agent:
    def __init__(self, name):
        self.name = name

    def run(self):
        raise NotImplementedError("Subclasses should implement this method.")

    def report(self):
        raise NotImplementedError("Subclasses should implement this method.")

class ReconAgent(Agent):
    def run(self):
        # Implement reconnaissance logic here
        pass

    def report(self):
        # Implement reporting logic for reconnaissance here
        pass

class ExploitAgent(Agent):
    def run(self):
        # Implement exploitation logic here
        pass

    def report(self):
        # Implement reporting logic for exploitation here
        pass

class ValidateAgent(Agent):
    def run(self):
        # Implement validation logic here
        pass

    def report(self):
        # Implement reporting logic for validation here
        pass

class ReportAgent(Agent):
    def run(self):
        # Implement reporting logic here
        pass

    def report(self):
        # Implement final reporting logic here
        pass
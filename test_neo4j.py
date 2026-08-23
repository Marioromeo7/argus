from neo4j import GraphDatabase
try:
    driver = GraphDatabase.driver("bolt://localhost:7400", auth=("neo4j", "argus1234"))
    with driver.session() as session:
        result = session.run("RETURN 1")
        print("Neo4j: CONNECTED")
        print(f"Result: {result.single()}")
    driver.close()
except Exception as e:
    print(f"Neo4j: FAILED - {e}")

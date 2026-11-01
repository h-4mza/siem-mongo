from pyspark.sql import SparkSession

MONGO_URI = (
    "mongodb://mongo1:27018,"
    "mongo2:27019,"
    "mongo3:27020/"
    "?replicaSet=rs0"
)

DATABASE = "siem"

EXPECTED_COUNTS = {
    "users": 10000,
    "hosts": 2000,
    "authentications": 60500,
    "network_flows": 40500,
    "alerts": 3200,
    "ip_blacklist": 200,
}


def read_collection(spark, collection):
    return (
        spark.read
        .format("mongodb")
        .option("connection.uri", MONGO_URI)
        .option("database", DATABASE)
        .option("collection", collection)
        .load()
    )


def main():
    spark = (
        SparkSession.builder
        .appName("SIEM-MongoDB-Connection-Test")
        .getOrCreate()
    )

    print("\n" + "=" * 70)
    print("SPARK <-> MONGODB CONNECTION TEST")
    print("=" * 70)

    for collection, expected in EXPECTED_COUNTS.items():
        print(f"\n{'-' * 70}")
        print(f"Collection: {collection}")

        try:
            df = read_collection(spark, collection)

            print("\nSchema:")
            df.printSchema()

            count = df.count()

            print(f"\nDocuments found: {count}")
            print(f"Expected:        {expected}")

            if count == expected:
                print("STATUS: OK")
            else:
                print("STATUS: COUNT MISMATCH")

            if collection == "authentications":
                print("\nAuthentication results:")
                df.groupBy("result").count().show()

        except Exception as e:
            print(f"ERROR while reading {collection}")
            print(str(e))

    spark.stop()


if __name__ == "__main__":
    main()
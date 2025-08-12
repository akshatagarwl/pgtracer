#include <libpq-fe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
  const char *host = getenv("PGHOST") ? getenv("PGHOST") : "postgres";
  const char *port = getenv("PGPORT") ? getenv("PGPORT") : "5432";
  const char *user = getenv("PGUSER") ? getenv("PGUSER") : "testuser";
  const char *pass = getenv("PGPASSWORD") ? getenv("PGPASSWORD") : "testpass";
  const char *db = getenv("PGDATABASE") ? getenv("PGDATABASE") : "testdb";

  char connstr[512];
  snprintf(connstr, sizeof(connstr),
           "host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
           host, port, user, pass, db);

  printf("Connecting to PostgreSQL...\n");
  PGconn *conn = PQconnectdb(connstr);

  if (PQstatus(conn) != CONNECTION_OK) {
    fprintf(stderr, "Connection failed: %s", PQerrorMessage(conn));
    PQfinish(conn);
    return 1;
  }

  printf("Connected successfully\n");

  const char *queries[] = {
      "SELECT version()",          "SELECT now()",
      "SELECT pg_backend_pid()",   "SELECT current_user",
      "SELECT inet_server_addr()",
  };

  for (int i = 0; i < 5; i++) {
    printf("Executing query %d: %s\n", i + 1, queries[i]);

    if (!PQsendQuery(conn, queries[i])) {
      fprintf(stderr, "Query %d failed: %s", i + 1, PQerrorMessage(conn));
      continue;
    }

    PGresult *res = PQgetResult(conn);
    if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
      printf("Query %d result: %s\n", i + 1, PQgetvalue(res, 0, 0));
    }
    PQclear(res);

    while ((res = PQgetResult(conn)) != NULL) {
      PQclear(res);
    }

    sleep(2);
  }

  PQfinish(conn);
  printf("Completed all queries\n");
  return 0;
}

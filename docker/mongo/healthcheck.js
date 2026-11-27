// Healthcheck de MongoDB sin credenciales en la línea de comandos (no aparecen en `ps` ni en
// `docker inspect` del comando). Lee el usuario root del entorno del propio contenedor.
// Inicia el replica set la primera vez (host localhost:27017 para apps ejecutadas en el host) y
// sale con 0 solo cuando este nodo es PRIMARY.
let healthy = false;
try {
  const conn = new Mongo("mongodb://localhost:27017/?directConnection=true");
  const admin = conn.getDB("admin");
  admin.auth(process.env.MONGO_INITDB_ROOT_USERNAME, process.env.MONGO_INITDB_ROOT_PASSWORD);
  try {
    healthy = admin.adminCommand({ replSetGetStatus: 1 }).myState === 1;
  } catch (e) {
    admin.adminCommand({
      replSetInitiate: { _id: "rs0", members: [{ _id: 0, host: "localhost:27017" }] },
    });
  }
} catch (e) {
  // sin conexión o credenciales todavía no creadas: aún no está sano
}
quit(healthy ? 0 : 1);


document.addEventListener("DOMContentLoaded", () => {
    actualizarBadgeNotificaciones();
    setInterval(actualizarBadgeNotificaciones, 5000);
});

async function actualizarBadgeNotificaciones() {
    try {
        const res = await fetch("/notificaciones/cantidad");
        const data = await res.json();

        const badge = document.getElementById("notificacion-badge");

        if (!badge) {
            console.log("badge no encontrado");
            return;
        }

        console.log("Cantidad notificaciones:", data.cantidad);

        if (data.cantidad > 0) {
            badge.textContent = data.cantidad;
            badge.style.display = "flex";   // 👈 fuerza a mostrarse
        } else {
            badge.style.display = "none";
        }

    } catch (err) {
        console.error("Error cargando notificaciones:", err);
    }
}

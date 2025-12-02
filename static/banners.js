
document.addEventListener("DOMContentLoaded", () => {
    const slides = document.querySelectorAll(".banner-slide");
    const prevBtn = document.querySelector(".prev-banner");
    const nextBtn = document.querySelector(".next-banner");
    const dotsContainer = document.querySelector(".banner-dots");

    let index = 0;

    // Crear puntos
    slides.forEach((s, i) => {
        const dot = document.createElement("div");
        dot.addEventListener("click", () => goToSlide(i));
        dotsContainer.appendChild(dot);
    });

    const dots = dotsContainer.querySelectorAll("div");
    dots[0].classList.add("active-dot");

    function updateSlider() {
        slides.forEach(s => s.classList.remove("active"));
        slides[index].classList.add("active");

        dots.forEach(d => d.classList.remove("active-dot"));
        dots[index].classList.add("active-dot");
    }

    function nextSlide() {
        index = (index + 1) % slides.length;
        updateSlider();
    }

    function prevSlide() {
        index = (index - 1 + slides.length) % slides.length;
        updateSlider();
    }

    function goToSlide(i) {
        index = i;
        updateSlider();
    }

    nextBtn.addEventListener("click", nextSlide);
    prevBtn.addEventListener("click", prevSlide);

    // Auto-slide cada 5 segundos
    setInterval(nextSlide, 5000);
});

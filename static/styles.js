function animation() {
  AOS.init({
    duration: 1200,
  });
}

animation();

const hamburger = document.querySelector(".hamburger");
const links = document.querySelector(".links");

hamburger.addEventListener("click", mobileMenu);

function mobileMenu() {
  hamburger.classList.toggle("active");
  links.classList.toggle("active");
}

const navLink = document.querySelectorAll(".nav-link");

navLink.forEach((n) => n.addEventListener("click", closeMenu));

function closeMenu() {
  hamburger.classList.remove("active");
  links.classList.remove("active");
}

let prevScroll = window.pageYOffset;
window.onscroll = function () {
  let currentScroll = window.pageYOffset;
  if (prevScroll > currentScroll) {
    document.getElementById("nav").style.top = "0";
  } else {
    document.getElementById("nav").style.top = "-90px";
  }
  prevScroll = currentScroll;
};

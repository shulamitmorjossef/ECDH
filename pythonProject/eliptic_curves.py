import numpy as np
import matplotlib.pyplot as plt

# פרמטרים של העקומה y^2 = x^3 + ax + b
a = -1
b = 1

x = np.linspace(-2, 2, 400)
y_square = x**3 + a*x + b
y_pos = np.sqrt(np.maximum(y_square, 0))
y_neg = -y_pos

plt.plot(x, y_pos, label='Elliptic Curve')
plt.plot(x, y_neg)

# דוגמה לנקודה על העקומה
Px = 0.5
Py = np.sqrt(Px**3 + a*Px + b)
plt.plot(Px, Py, 'ro', label='Point P')

plt.title('Elliptic Curve y^2 = x^3 + ax + b')
plt.xlabel('x')
plt.ylabel('y')
plt.legend()
plt.grid(True)
plt.show()

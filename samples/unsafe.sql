SELECT * FROM employees;

DELETE FROM employees;

UPDATE employees SET salary = 0;

DROP TABLE employees;

TRUNCATE TABLE departments;

SELECT e.name, d.name
FROM employees e
CROSS JOIN departments d;

DELETE FROM employees WHERE 1 = 1;

SELECT name FROM employees;

SELECT name FROM employees;

SELECT name
FROM employees
WHERE id IN (
    SELECT employee_id
    FROM projects
    WHERE department_id IN (
        SELECT id
        FROM departments
        WHERE manager_id IN (
            SELECT id FROM managers
        )
    )
);

-- Safe examples

SELECT name, salary
FROM employees
WHERE id = 10;

UPDATE employees
SET salary = 50000
WHERE id = 10;

DELETE FROM employees
WHERE id = 10;

SELECT COUNT(*) FROM employees;
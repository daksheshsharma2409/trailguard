const express = require('express');

const ordersRouter = express.Router();

ordersRouter.get('/', (_req, res) => {
  res.json({ orders: [] });
});

module.exports = ordersRouter;

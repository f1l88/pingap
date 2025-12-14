## Архитектура проекта

### Основные слои:

**1. Entry points (точки входа)**
- `main.tsx` - корневой рендеринг
- `App.tsx` - главный компонент приложения
- `index.css` - глобальные стили

**2. Routing**
- `routers.tsx` - маршрутизация приложения
- `Root.tsx` - корневой layout

**3. Pages (`/pages`)**
- Компоненты-страницы для каждого маршрута
- Пример: `Home.tsx`, `Login.tsx`, `Config.tsx`

**4. Components (`/components`)**
- `ui/` - базовые UI компоненты (button, input, card, etc.)
- Бизнес-компоненты: `header.tsx`, `sidebar-nav.tsx`, `ex-form.tsx`

**5. State Management (`/states`)**
- Zustand/Redux stores: `basic.ts`, `config.ts`, `token.ts`

**6. Utilities**
- `helpers/` - HTTP запросы, утилиты
- `lib/` - общие утилиты
- `hooks/` - кастомные хуки
- `constants.ts` - константы приложения

**7. Internationalization (`/i18n`)**
- Многоязычная поддержка (en, zh)

## Как подключить новую страницу

### Шаг 1: Создать компонент страницы

В папке `pages` создаем новый файл, например `Users.tsx`:

```tsx
// pages/Users.tsx
import React from 'react';

const Users = () => {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Пользователи</h1>
      <p>Страница управления пользователями</p>
      {/* Ваш контент */}
    </div>
  );
};

export default Users;
```

### Шаг 2: Добавить маршрут в routers.tsx

```tsx
// routers.tsx
import { createBrowserRouter } from 'react-router-dom';
import Root from './pages/Root';
import Home from './pages/Home';
import Login from './pages/Login';
// Импортируем новую страницу
import Users from './pages/Users';

export const router = createBrowserRouter([
  {
    path: '/',
    element: <Root />,
    children: [
      {
        index: true,
        element: <Home />,
      },
      {
        path: 'users', // новый маршрут
        element: <Users />,
      },
      {
        path: 'config',
        element: <Config />,
      },
      // ... остальные маршруты
    ],
  },
  {
    path: '/login',
    element: <Login />,
  },
]);
```

### Шаг 3: Обновить навигацию (опционально)

Если нужно добавить страницу в боковое меню, редактируем `sidebar-nav.tsx`:

```tsx
// components/sidebar-nav.tsx
import { Link, useLocation } from 'react-router-dom';

export function SidebarNav() {
  const { pathname } = useLocation();

  const navItems = [
    {
      title: 'Главная',
      href: '/',
    },
    {
      title: 'Пользователи', // новый пункт меню
      href: '/users',
    },
    {
      title: 'Конфигурация',
      href: '/config',
    },
    // ... остальные пункты
  ];

  return (
    <nav className="flex flex-col space-y-2">
      {navItems.map((item) => (
        <Link
          key={item.href}
          to={item.href}
          className={`px-3 py-2 rounded-lg transition-colors ${
            pathname === item.href
              ? 'bg-blue-100 text-blue-700'
              : 'hover:bg-gray-100'
          }`}
        >
          {item.title}
        </Link>
      ))}
    </nav>
  );
}
```

### Шаг 4: Добавить переводы (опционально)

В соответствующих файлах переводов:

```ts
// i18n/en.ts
export const en = {
  home: 'Home',
  users: 'Users', // новый перевод
  config: 'Configuration',
  // ...
};

// i18n/zh.ts
export const zh = {
  home: '首页',
  users: '用户', // новый перевод
  config: '配置',
  // ...
};
```

## Расширенный пример с состоянием

Если страница требует управления состоянием:

```tsx
// pages/Users.tsx
import React from 'react';
import { useUsersStore } from '../states/users'; // создаем новый store
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';

const Users = () => {
  const { users, loading, fetchUsers } = useUsersStore();

  React.useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  if (loading) {
    return <div>Загрузка...</div>;
  }

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Пользователи</h1>
        <Button>Добавить пользователя</Button>
      </div>
      
      <div className="space-y-4">
        {users.map((user) => (
          <div key={user.id} className="p-4 border rounded-lg">
            <h3>{user.name}</h3>
            <p>{user.email}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Users;
```

И создаем соответствующий store:

```ts
// states/users.ts
import { create } from 'zustand';

interface User {
  id: number;
  name: string;
  email: string;
}

interface UsersState {
  users: User[];
  loading: boolean;
  fetchUsers: () => Promise<void>;
}

export const useUsersStore = create<UsersState>((set) => ({
  users: [],
  loading: false,
  fetchUsers: async () => {
    set({ loading: true });
    try {
      // Здесь ваш API call
      const response = await fetch('/api/users');
      const users = await response.json();
      set({ users });
    } catch (error) {
      console.error('Error fetching users:', error);
    } finally {
      set({ loading: false });
    }
  },
}));
```

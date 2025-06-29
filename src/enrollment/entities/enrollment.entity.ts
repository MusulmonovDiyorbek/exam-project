import { Course } from "src/course/entities/course.entity";
import { User } from "src/users/entities/user.entity";
import { CreateDateColumn, Entity, ManyToOne, PrimaryGeneratedColumn } from "typeorm";

@Entity()
export class Enrollment {
  @PrimaryGeneratedColumn()
  id: number;

  @ManyToOne(() => User, user => user.enrollments)
  user: User;

  @ManyToOne(() => Course, course => course.enrollments)
  course: Course;

  @CreateDateColumn()
  paidAt: Date;
}
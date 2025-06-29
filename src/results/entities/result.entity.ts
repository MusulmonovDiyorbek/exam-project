import { Assignment } from "src/assignment/entities/assignment.entity";
import { User } from "src/users/entities/user.entity";
import { Column, CreateDateColumn, Entity, JoinColumn, ManyToOne, OneToOne, PrimaryGeneratedColumn } from "typeorm";

@Entity()
export class Result {
    @PrimaryGeneratedColumn()
    id: number;

    @OneToOne(() => Assignment, (assignment) => assignment.result)
    @JoinColumn()
    assignment: Assignment

    @ManyToOne(() => User)
    teacher: User

    @Column()
    score: number;

    @Column('text', { nullable: true })
    feedback: string;

    @CreateDateColumn()
    gradedAt: Date
}

